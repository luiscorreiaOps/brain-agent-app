package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// MemoryMetadata holds optional structured fields for a stored fact -- every
// field's zero value means "not set", matching this plugin's existing
// "0/empty means original/default behavior" convention (see
// maintenanceMinOverlapRatio above). Status defaults to "approved" when
// empty; the only other real value is "pending" (see suggestMemory), used by
// the Brain Hub approval queue for LLM-inferred suggestions -- explicit
// store_memory/upsert_memory calls always land as "approved" immediately.
type MemoryMetadata struct {
	Type       string
	Tags       string // comma-separated
	Service    string
	Namespace  string
	Source     string // e.g. "manual" (default), "llm-suggested", "auto-learn-alerts"
	Confidence float64
	ExpiresAt  *time.Time
	Status     string
	// Author names the person who curated/confirmed this fact -- distinct
	// from Source (which describes HOW the fact entered the system, e.g.
	// "manual"/"llm-suggested"). Chiefly useful for type="runbook" facts
	// (see retrieve_runbook) so a reader knows who to ask about it, but not
	// restricted to that type.
	Author string
}

// encodeForStorage returns what to actually write into memory_store.fact
// (and the is_encrypted flag to store alongside it) for one plaintext
// fact, honoring the current atRestEncryptionEnabled setting. Shared by
// StoreMemory and CondenseMemory's golden-record insert so the two can
// never drift on this decision.
func (a *App) encodeForStorage(plaintext string) (storedValue string, isEncrypted int, err error) {
	if !a.atRestEncryptionEnabled {
		return plaintext, 0, nil
	}
	encrypted, err := a.Encrypt(plaintext)
	if err != nil {
		return "", 0, err
	}
	return encrypted, 1, nil
}

// decryptTrackingFailures decrypts fact if isEncrypted, falling back to the
// raw (still-encrypted) value on failure like every call site already did
// -- the only change is recording that it happened, for diagnostics.
func (a *App) decryptTrackingFailures(fact string, isEncrypted bool) string {
	if !isEncrypted {
		return fact
	}
	dec, err := a.Decrypt(fact)
	if err != nil {
		a.decryptFailureMu.Lock()
		a.decryptFailureCount++
		a.lastDecryptFailureAt = time.Now()
		a.decryptFailureMu.Unlock()
		return fact
	}
	return dec
}

// decryptFailureStats reports the running total for brain_diagnostics.
func (a *App) decryptFailureStats() (count int, lastAt time.Time) {
	a.decryptFailureMu.Lock()
	defer a.decryptFailureMu.Unlock()
	return a.decryptFailureCount, a.lastDecryptFailureAt
}

// configureMaintenance applies the admin-configured values from
// Settings (BrainConfig.tsx's "Storage & Database"/"RAG" sections) --
// zero/negative values keep this plugin's original hardcoded defaults.
func (a *App) configureMaintenance(maxDbSizeMB, retentionDays, maxResults int, minOverlapRatio float64) {
	if maxDbSizeMB > 0 {
		a.maintenanceMaxDbSizeMB = maxDbSizeMB
	}
	if retentionDays > 0 {
		a.maintenanceRetentionDays = retentionDays
	}
	if maxResults > 0 {
		a.maintenanceMaxResults = maxResults
	}
	if minOverlapRatio > 0 {
		a.maintenanceMinOverlapRatio = minOverlapRatio
	}
}

// InitDB initializes the SQLite database, its encryption key, and the
// search index key. providedEncryptionKey, when non-empty, is a
// base64-encoded 32-byte AES key from Settings.EncryptionKey (secureJsonData)
// used directly instead of the local brain_aes.key file (security-audit
// finding L3) -- empty keeps the existing local-file behavior.
func (a *App) InitDB(dataDir string, pluginName string, providedEncryptionKey string) error {
	// Initialize LGPD encryption at rest
	if err := a.InitCrypto(dataDir, providedEncryptionKey); err != nil {
		return fmt.Errorf("failed to init crypto: %w", err)
	}

	// Separate key for the HMAC search token index (search_index.go) --
	// deliberately not derived from aesKey above (key separation).
	if err := a.InitSearchIndexKey(dataDir); err != nil {
		return fmt.Errorf("failed to init search index key: %w", err)
	}

	// Ensure the directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, fmt.Sprintf("%s.db", pluginName))
	a.dbFilePath = dbPath
	var err error

	// Add pragmas for better SQLite concurrency and resource management
	a.db, err = sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	a.db.SetMaxOpenConns(1)
	a.db.SetMaxIdleConns(1)

	// Invalidate the duplicate-facts cache -- it's keyed to this App
	// instance, not to a specific *sql.DB, so a new/replaced database (a
	// real instance reload, or each test's own fresh temp DB) must not
	// serve a stale count computed against a database that's no longer
	// this one.
	a.duplicateFactsCacheMu.Lock()
	a.duplicateFactsCacheTime = time.Time{}
	a.duplicateFactsCacheMu.Unlock()

	// Create tables if they don't exist
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS memory_store (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project TEXT NOT NULL,
		fact TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_encrypted BOOLEAN DEFAULT 0,
		type TEXT,
		tags TEXT,
		service TEXT,
		namespace TEXT,
		source TEXT,
		confidence REAL,
		expires_at DATETIME,
		status TEXT NOT NULL DEFAULT 'approved'
	);
	CREATE INDEX IF NOT EXISTS idx_project ON memory_store(project);
	CREATE TABLE IF NOT EXISTS memory_index (
		memory_id INTEGER NOT NULL,
		project TEXT NOT NULL,
		token_hmac TEXT NOT NULL,
		hmac_scheme INTEGER DEFAULT 1
	);
	CREATE INDEX IF NOT EXISTS idx_search_token ON memory_index(project, token_hmac);
	CREATE INDEX IF NOT EXISTS idx_search_memory_id ON memory_index(memory_id);
	`

	_, err = a.db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to initialize tables: %w", err)
	}

	// Safely attempt to add columns from older versions -- each guarded the
	// same way, so an install that already has a column is a silent no-op
	// and one that doesn't gets it added with a safe default (existing rows
	// backfill to that default, e.g. every pre-existing fact becomes
	// status='approved', never leaving old data invisible to search).
	migrationColumns := []string{
		"ALTER TABLE memory_store ADD COLUMN is_encrypted BOOLEAN DEFAULT 0",
		"ALTER TABLE memory_store ADD COLUMN type TEXT",
		"ALTER TABLE memory_store ADD COLUMN tags TEXT",
		"ALTER TABLE memory_store ADD COLUMN service TEXT",
		"ALTER TABLE memory_store ADD COLUMN namespace TEXT",
		"ALTER TABLE memory_store ADD COLUMN source TEXT",
		"ALTER TABLE memory_store ADD COLUMN confidence REAL",
		"ALTER TABLE memory_store ADD COLUMN expires_at DATETIME",
		"ALTER TABLE memory_store ADD COLUMN status TEXT NOT NULL DEFAULT 'approved'",
		"ALTER TABLE memory_store ADD COLUMN pii_detected BOOLEAN DEFAULT 0",
		"ALTER TABLE memory_store ADD COLUMN embedding TEXT",
		"ALTER TABLE memory_store ADD COLUMN author TEXT",
		"ALTER TABLE memory_store ADD COLUMN last_accessed DATETIME",
		"ALTER TABLE memory_index ADD COLUMN hmac_scheme INTEGER DEFAULT 1",
	}
	for _, stmt := range migrationColumns {
		if _, err := a.db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			log.DefaultLogger.Warn("Migration warning", "error", err)
		}
	}

	// Security-audit finding L5: queries filter by (project, status,
	// expires_at) together (e.g. SearchMemory, GetProjectStats), but the
	// only index available was on project alone. Created here, after the
	// migrationColumns loop above, since status/expires_at don't exist yet
	// on an install upgrading from before those columns existed --
	// creating this index any earlier would fail with "no such column" on
	// exactly the installs that most need the fix.
	if _, err := a.db.Exec("CREATE INDEX IF NOT EXISTS idx_memory_project_status_expires ON memory_store(project, status, expires_at)"); err != nil {
		log.DefaultLogger.Warn("Migration warning: failed to create composite index", "error", err)
	}

	// Security-audit finding M4: reindex any memory_index row still on the
	// pre-project-scoped HMAC scheme. HMACs are one-way -- there's no way
	// to "upgrade" an existing row in place, so stale rows are deleted and
	// backfillSearchIndexIfNeeded below recreates them (it already treats
	// any fact missing an index row as needing one). A no-op after the
	// first startup post-upgrade, once every row is on currentHMACScheme.
	if res, err := a.db.Exec("DELETE FROM memory_index WHERE hmac_scheme IS NULL OR hmac_scheme < ?", currentHMACScheme); err != nil {
		log.DefaultLogger.Warn("Migration warning: failed to clear pre-project-scoped search index rows", "error", err)
	} else if n, _ := res.RowsAffected(); n > 0 {
		log.DefaultLogger.Info("search index: cleared rows on an old HMAC scheme, will be reindexed", "count", n)
	}

	// Start background self-healing routine for scalability and data descale
	a.startHealthMaintenance(dbPath)

	// Populate memory_index for any fact written before this index existed
	// (or just cleared by the migration above).
	a.backfillSearchIndexIfNeeded(context.Background())

	log.DefaultLogger.Info("Brain database initialized with LGPD encryption support", "path", dbPath)
	return nil
}

// PingDB verifies if the database connection is alive and initialized
func (a *App) PingDB() error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	return a.db.Ping()
}

// startHealthMaintenance runs a background self-healing goroutine, tracked
// via a.maintenanceStopMu/a.currentMaintenanceStop so InitDB can be called
// again (a real database re-init, e.g. after handleCryptoReset) without
// leaking a previous, now-orphaned goroutine still ticking against a stale
// dbPath every time (security-audit finding L4: it used to run forever with
// no cancellation mechanism at all).
func (a *App) startHealthMaintenance(dbPath string) {
	a.maintenanceStopMu.Lock()
	if a.currentMaintenanceStop != nil {
		a.currentMaintenanceStop()
	}
	stop := make(chan struct{})
	a.currentMaintenanceStop = func() { close(stop) }
	a.maintenanceStopMu.Unlock()

	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.runMaintenanceOnce(dbPath)
			}
		}
	}()
}

// StopHealthMaintenance cancels the currently running maintenance
// goroutine, if any -- called from App.Dispose so a plugin instance
// shutting down doesn't leave it running.
func (a *App) StopHealthMaintenance() {
	a.maintenanceStopMu.Lock()
	defer a.maintenanceStopMu.Unlock()
	if a.currentMaintenanceStop != nil {
		a.currentMaintenanceStop()
		a.currentMaintenanceStop = nil
	}
}

// runMaintenanceOnce is startHealthMaintenance's per-tick body, pulled out
// so a test can run it deterministically instead of waiting on a 15-minute
// ticker.
func (a *App) runMaintenanceOnce(dbPath string) {
	if a.db == nil {
		return
	}

	// 1. Anticipate context explosion: Evict oldest data if we exceed 100,000 facts
	var count int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM memory_store").Scan(&count); err == nil {
		if count > 100000 {
			// Graceful degradation: Delete oldest 10%
			deleteLimit := count / 10
			log.DefaultLogger.Info("Brain database scaling down: evicting oldest memories to maintain RAG performance", "evicting_rows", deleteLimit)
			if _, err := a.db.Exec("DELETE FROM memory_store WHERE id IN (SELECT id FROM memory_store ORDER BY created_at ASC LIMIT ?)", deleteLimit); err != nil {
				log.DefaultLogger.Warn("Brain database eviction failed", "error", err)
			}
		}
	}

	// 2. Anticipate Disk Full: Monitor physical file size against
	// the admin-configured (or default 500MB) limit.
	info, err := os.Stat(dbPath)
	if err == nil {
		maxBytes := int64(a.maintenanceMaxDbSizeMB) * 1024 * 1024
		if info.Size() > maxBytes {
			log.DefaultLogger.Warn("Brain database physical size exceeded configured limit, triggering emergency prune and vacuum", "limit_mb", a.maintenanceMaxDbSizeMB)
			// Emergency descale: delete oldest 20%
			if _, err := a.db.Exec("DELETE FROM memory_store WHERE id IN (SELECT id FROM memory_store ORDER BY created_at ASC LIMIT (SELECT COUNT(*)/5 FROM memory_store))"); err != nil {
				log.DefaultLogger.Warn("Brain database emergency prune failed", "error", err)
			}
			if _, err := a.db.Exec("VACUUM"); err != nil { // Reclaim physical disk space
				log.DefaultLogger.Warn("Brain database VACUUM failed", "error", err)
			}
		}
	}

	// 3. Data Retention: delete facts older than the admin-configured
	// window (0 = retention disabled, this plugin's original behavior --
	// facts never expired by age).
	if a.maintenanceRetentionDays > 0 {
		cutoff := fmt.Sprintf("-%d days", a.maintenanceRetentionDays)
		if res, err := a.db.Exec("DELETE FROM memory_store WHERE created_at < datetime('now', ?)", cutoff); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				log.DefaultLogger.Info("Brain database retention: deleted facts past the configured retention window", "deleted_rows", n, "retention_days", a.maintenanceRetentionDays)
			}
		}
	}

	// 4. Structured-memory expiry: delete facts whose optional expires_at
	// has passed (NULL/unset expires_at never expires -- independent of the
	// day-based retention window above, which applies to every fact
	// regardless of an explicit expiry).
	expiredIDs := a.expiredMemoryIDs()
	if len(expiredIDs) > 0 {
		if res, err := a.db.Exec("DELETE FROM memory_store WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP"); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				log.DefaultLogger.Info("Brain database expiry: deleted facts past their expires_at", "deleted_rows", n)
			}
		}
		for _, id := range expiredIDs {
			a.removeFactFromIndex(context.Background(), id)
		}
	}
}

// expiredMemoryIDs returns the ids of every fact whose expires_at has
// already passed -- collected before the DELETE above so their
// memory_index rows can be cleaned up too (the DELETE itself has no way to
// report which rows it removed).
func (a *App) expiredMemoryIDs() []int64 {
	rows, err := a.db.Query("SELECT id FROM memory_store WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP")
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// CloseDB gracefully closes the database connection.
func (a *App) CloseDB() error {
	if a.db != nil {
		err := a.db.Close()
		a.db = nil
		return err
	}
	return nil
}

// StoreMemory stores an encrypted fact in the database for a specific
// project, with no structured metadata (equivalent to
// StoreMemoryWithMetadata(ctx, project, fact, nil)) -- kept as its own
// function so every existing caller/test is unaffected by the metadata
// addition below.
func (a *App) StoreMemory(ctx context.Context, project, fact string) error {
	return a.storeMemoryRecord(ctx, project, fact, nil)
}

// StoreMemoryWithMetadata is StoreMemory plus optional structured metadata
// (type/tags/service/namespace/source/confidence/expires_at/status). A nil
// meta behaves identically to StoreMemory.
func (a *App) StoreMemoryWithMetadata(ctx context.Context, project, fact string, meta *MemoryMetadata) error {
	return a.storeMemoryRecord(ctx, project, fact, meta)
}

// nullIfEmpty maps an empty string to real SQL NULL instead of storing "" --
// keeps type/tags/service/namespace genuinely absent (not just blank) for
// filtering (`WHERE service = ?` should never match an unrelated fact that
// merely also has no service set).
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *App) storeMemoryRecord(ctx context.Context, project, fact string, meta *MemoryMetadata) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	fact = strings.TrimSpace(fact)
	var piiDetected bool
	if a.piiDetectionEnabled {
		piiDetected = detectPII(fact)
	}

	storedValue, isEncrypted, err := a.encodeForStorage(fact)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	status := "approved"
	var typ, tags, service, namespace, source, author string
	var confidenceVal any
	var expiresAtVal any
	if meta != nil {
		if meta.Status != "" {
			status = meta.Status
		}
		typ, tags, service, namespace, source, author = meta.Type, meta.Tags, meta.Service, meta.Namespace, meta.Source, meta.Author
		if meta.Confidence > 0 {
			confidenceVal = meta.Confidence
		}
		if meta.ExpiresAt != nil {
			expiresAtVal = meta.ExpiresAt.UTC().Format("2006-01-02 15:04:05")
		}
	}
	if source == "" {
		source = "manual"
	}

	result, err := a.db.ExecContext(ctx,
		`INSERT INTO memory_store (project, fact, is_encrypted, type, tags, service, namespace, source, confidence, expires_at, status, pii_detected, author)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		project, storedValue, isEncrypted, nullIfEmpty(typ), nullIfEmpty(tags), nullIfEmpty(service), nullIfEmpty(namespace), source, confidenceVal, expiresAtVal, status, piiDetected, nullIfEmpty(author))
	if err != nil {
		return err
	}

	// Index the real plaintext (never the ciphertext -- see search_index.go)
	// for fast, encryption-safe search. A failure here doesn't fail the
	// write: the fact is safely stored either way.
	if memoryID, idErr := result.LastInsertId(); idErr == nil {
		a.indexFact(ctx, memoryID, project, fact)
		a.storeEmbeddingIfConfigured(ctx, memoryID, fact)
	}
	return nil
}

// storeEmbeddingIfConfigured computes and persists fact's embedding when an
// embedding endpoint is configured -- a no-op (not an error) when it isn't,
// and best-effort otherwise: a failed embedding call (endpoint down, model
// unreachable) never fails the write itself, it just leaves this fact
// without a vector, so it's still found via the lexical fallback path in
// SearchMemory.
func (a *App) storeEmbeddingIfConfigured(ctx context.Context, memoryID int64, fact string) {
	if !a.embeddingsConfigured() {
		return
	}
	vec, err := a.computeEmbedding(ctx, fact)
	if err != nil {
		log.DefaultLogger.Warn("failed to compute embedding for a new fact, falling back to lexical search for it", "error", err)
		return
	}
	encoded, err := encodeEmbedding(vec)
	if err != nil {
		return
	}
	if _, err := a.db.ExecContext(ctx, "UPDATE memory_store SET embedding = ? WHERE id = ?", encoded, memoryID); err != nil {
		log.DefaultLogger.Warn("failed to persist embedding for a new fact", "error", err)
	}
}

// canonicalizeFact normalizes a fact for duplicate comparison -- case and
// whitespace shouldn't make "The Vault pod restarted" and "the vault pod
// restarted " count as two different memories.
func canonicalizeFact(fact string) string {
	return strings.Join(strings.Fields(strings.ToLower(fact)), " ")
}

// UpsertMemory stores fact under project unless a canonically-identical
// fact (same words, case/whitespace-insensitive) is already there, in which
// case it's a no-op -- store_memory alone happily writes the same fact
// twice with nothing to stop it. Facts are AES-GCM encrypted with a random
// nonce each time (crypto.go), so this can only be done by decrypting and
// comparing in application code, the same constraint CountDuplicateFacts
// works around. Returns inserted=false when the fact was already present.
//
// This dedupes exact repeats; it does not "reinforce" (bump a
// count/timestamp on) a near-duplicate or merge similar-but-not-identical
// facts -- there's no existing per-fact identity (key/hash column) to
// reinforce, and fuzzy similarity would need a real similarity metric this
// plugin doesn't have (see SearchMemory's TF-IDF-lite scoring, which isn't
// normalized for a same/different judgement).
func (a *App) UpsertMemory(ctx context.Context, project, fact string) (inserted bool, err error) {
	return a.upsertMemoryRecord(ctx, project, fact, nil)
}

// UpsertMemoryWithMetadata is UpsertMemory plus optional structured metadata,
// stored via StoreMemoryWithMetadata when the fact is genuinely new.
func (a *App) UpsertMemoryWithMetadata(ctx context.Context, project, fact string, meta *MemoryMetadata) (inserted bool, err error) {
	return a.upsertMemoryRecord(ctx, project, fact, meta)
}

func (a *App) upsertMemoryRecord(ctx context.Context, project, fact string, meta *MemoryMetadata) (inserted bool, err error) {
	if a.db == nil {
		return false, fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	fact = strings.TrimSpace(fact)
	canonical := canonicalizeFact(fact)
	if canonical == "" {
		return false, fmt.Errorf("fact is empty")
	}

	rows, err := a.db.QueryContext(ctx, "SELECT fact, is_encrypted FROM memory_store WHERE project = ?", project)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var existing string
		var isEncrypted bool
		if err := rows.Scan(&existing, &isEncrypted); err != nil {
			continue
		}
		existing = a.decryptTrackingFailures(existing, isEncrypted)
		if canonicalizeFact(existing) == canonical {
			_ = rows.Close()
			return false, nil
		}
	}
	_ = rows.Close()

	if err := a.storeMemoryRecord(ctx, project, fact, meta); err != nil {
		return false, err
	}
	return true, nil
}

// scoredFact pairs a decrypted fact with its TF-IDF-lite relevance score.
// Weighted is Score with memoryDecayWeight applied -- what ranking actually
// sorts by; Score is kept as the raw lexical score for reference/tests.
type scoredFact struct {
	ID       int64
	Fact     string
	Score    int
	Weighted float64
}

// scoreFact scores one already-decrypted fact against query/terms -- the
// exact-phrase-bonus + per-term-match rule shared by both SearchMemory's
// index-narrowed path and its full-scan fallback, so the two can never
// silently drift into ranking facts differently depending on which path
// happened to run.
func scoreFact(fact, query string, terms []string) (score int, matchedTerms int) {
	factLower := strings.ToLower(fact)
	if strings.Contains(factLower, strings.ToLower(query)) {
		score += 5 // Exact phrase bonus
	}
	for _, term := range terms {
		if strings.Contains(factLower, term) {
			score++
			matchedTerms++
		}
	}
	return score, matchedTerms
}

// passesOverlapThreshold applies "Semantic Overlap (Threshold)"
// (BrainConfig.tsx) -- the fraction of the query's own terms found in this
// fact. 0 (default) means no filtering, matching this plugin's original
// behavior.
func (a *App) passesOverlapThreshold(matchedTerms, totalTerms int) bool {
	if a.maintenanceMinOverlapRatio <= 0 || totalTerms == 0 {
		return true
	}
	return float64(matchedTerms)/float64(totalTerms) >= a.maintenanceMinOverlapRatio
}

// searchViaIndex tries the HMAC token index first (see search_index.go):
// only the facts it names as candidates ever get decrypted, instead of
// every fact in the project. Returns ok=false when the index couldn't
// narrow anything down (no usable query tokens, or zero candidates) --
// SearchMemory falls back to its original full-scan behavior in that case,
// never treating "the index has nothing to say" as "no matches exist".
func (a *App) searchViaIndex(ctx context.Context, project, query string) (results []string, ok bool) {
	candidateIDs, usable := a.candidateIDsFromIndex(ctx, project, query)
	if !usable || len(candidateIDs) == 0 {
		return nil, false
	}

	terms := strings.Fields(strings.ToLower(query))
	var scored []scoredFact
	for id := range candidateIDs {
		fact, isEncrypted, ageDays, found := a.encryptedFactByID(ctx, id)
		if !found {
			continue
		}
		fact = a.decryptTrackingFailures(fact, isEncrypted)
		score, matchedTerms := scoreFact(fact, query, terms)
		if !a.passesOverlapThreshold(matchedTerms, len(terms)) {
			continue
		}
		if score > 0 {
			weight := memoryDecayWeight(ageDays)
			scored = append(scored, scoredFact{ID: id, Fact: fact, Score: score, Weighted: float64(score) * weight})
		}
	}
	if len(scored) == 0 {
		return nil, false
	}

	sort.Slice(scored, func(i, j int) bool { return scored[i].Weighted > scored[j].Weighted })
	var matchedIDs []int64
	for i, match := range scored {
		if i >= a.maintenanceMaxResults {
			break
		}
		results = append(results, match.Fact)
		matchedIDs = append(matchedIDs, match.ID)
	}
	a.touchLastAccessed(ctx, matchedIDs)
	return results, true
}

// SearchMemory searches the memory store securely by decrypting at runtime.
// When semanticSearch is false, scoring is skipped entirely and the most
// recent facts are returned as-is -- cheaper and more predictable than the
// TF-IDF-lite scoring below, useful for small/mostly-chronological projects
// (see Settings.SemanticSearchEnabled).
func (a *App) SearchMemory(ctx context.Context, project, query string, semanticSearch bool) ([]string, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}

	if semanticSearch && query != "" && a.embeddingsConfigured() {
		if results, ok := a.searchViaEmbeddings(ctx, project, query); ok {
			return results, nil
		}
		// No embedding could be obtained for the query, or no fact in this
		// project has one yet -- fall through to the lexical paths below.
	}

	if semanticSearch && query != "" {
		if results, ok := a.searchViaIndex(ctx, project, query); ok {
			return results, nil
		}
		// Index found nothing usable (short/stopword-only query, or truly
		// no match) -- fall through to the full-scan path below, same as
		// this plugin's original, pre-index behavior.
	}

	terms := strings.Fields(strings.ToLower(query))

	// Fetch all facts for the project (ordered by recent) to perform
	// in-memory search -- excludes pending suggestions (see the Brain Hub
	// approval queue) and facts past their expires_at, so neither ever
	// surfaces as a normal search result. ageDays feeds memoryDecayWeight
	// when semanticSearch scores facts below; the !semanticSearch (pure
	// recency) branch ignores it, unchanged from before decay existed.
	rows, err := a.db.QueryContext(ctx, "SELECT id, fact, is_encrypted, "+memoryDecayAgeDaysExpr+" FROM memory_store WHERE project = ? AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) ORDER BY created_at DESC", project)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var allDecrypted []string
	var scored []scoredFact

	for rows.Next() {
		var id int64
		var fact string
		var isEncrypted bool
		var ageDays sql.NullFloat64
		if err := rows.Scan(&id, &fact, &isEncrypted, &ageDays); err != nil {
			continue
		}

		// Decrypt if necessary (LGPD compliance)
		fact = a.decryptTrackingFailures(fact, isEncrypted)

		allDecrypted = append(allDecrypted, fact)

		if !semanticSearch {
			// Scoring disabled -- rows are already ordered by created_at
			// DESC, so allDecrypted alone is "most recent first".
			continue
		}

		score, matchedTerms := scoreFact(fact, query, terms)
		if !a.passesOverlapThreshold(matchedTerms, len(terms)) {
			continue
		}
		if score > 0 {
			weight := memoryDecayWeight(ageDays)
			scored = append(scored, scoredFact{ID: id, Fact: fact, Score: score, Weighted: float64(score) * weight})
		}
	}

	if !semanticSearch {
		if len(allDecrypted) > a.maintenanceMaxResults {
			return allDecrypted[:a.maintenanceMaxResults], nil
		}
		return allDecrypted, nil
	}

	// Sort by highest decay-weighted score first (Semantic Relevance)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Weighted > scored[j].Weighted
	})

	var topMatches []string
	var matchedIDs []int64
	for i, match := range scored {
		if i >= a.maintenanceMaxResults {
			break
		}
		topMatches = append(topMatches, match.Fact)
		matchedIDs = append(matchedIDs, match.ID)
	}

	// Fallback if no match
	if len(topMatches) == 0 {
		if len(allDecrypted) > 10 {
			return allDecrypted[:10], nil
		}
		return allDecrypted, nil
	}

	a.touchLastAccessed(ctx, matchedIDs)
	return topMatches, nil
}

// DeleteMemory removes a specific fact from a project.
func (a *App) DeleteMemory(ctx context.Context, project, fact string) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	fact = strings.TrimSpace(fact)

	rows, err := a.db.QueryContext(ctx, "SELECT id, fact, is_encrypted FROM memory_store WHERE project = ?", project)
	if err != nil {
		return err
	}

	targetID := -1
	for rows.Next() {
		var id int
		var dbFact string
		var isEncrypted bool
		if err := rows.Scan(&id, &dbFact, &isEncrypted); err == nil {
			dbFact = a.decryptTrackingFailures(dbFact, isEncrypted)
			if dbFact == fact {
				targetID = id
				break
			}
		}
	}
	_ = rows.Close()

	if targetID == -1 {
		return fmt.Errorf("fact not found")
	}

	_, err = a.db.ExecContext(ctx, "DELETE FROM memory_store WHERE id = ?", targetID)
	if err != nil {
		return err
	}
	a.removeFactFromIndex(ctx, int64(targetID))
	return nil
}

// GetProjectStats returns a map of project names to their fact count.
func (a *App) GetProjectStats(ctx context.Context) (map[string]int, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := a.db.QueryContext(ctx, "SELECT project, COUNT(*) FROM memory_store WHERE status = 'approved' GROUP BY project")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	stats := make(map[string]int)
	for rows.Next() {
		var project string
		var count int
		if err := rows.Scan(&project, &count); err != nil {
			return nil, err
		}
		stats[project] = count
	}
	return stats, nil
}

// ProjectsWithPendingFacts returns every distinct project name that has at
// least one pending suggestion -- including a project that has never had a
// single approved fact yet (so it would never appear in GetProjectStats).
// The Brain Hub UI uses this to know which projects to check for pending
// suggestions, instead of only checking projects it already knows about
// from the approved-facts stats.
func (a *App) ProjectsWithPendingFacts(ctx context.Context) ([]string, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	rows, err := a.db.QueryContext(ctx, "SELECT DISTINCT project FROM memory_store WHERE status = 'pending'")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var projects []string
	for rows.Next() {
		var project string
		if err := rows.Scan(&project); err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, nil
}

// duplicateFactsCacheTTL bounds how often CountDuplicateFacts actually
// re-scans and decrypts the whole memory_store table (security-audit
// finding C4) -- brain_diagnostics is now Editor/Admin-only (see
// requiresEditorOrAdmin), so the original Viewer-DoS vector is closed, but
// decrypting every row on every single diagnostics call is still wasteful
// for a value that doesn't need to be real-time.
const duplicateFactsCacheTTL = 10 * time.Minute

// CountDuplicateFacts counts exact-plaintext duplicate facts within the
// same project (e.g. store_memory called twice with the same fact --
// nothing today deduplicates on write). Facts are AES-GCM encrypted with a
// fresh random nonce each time (see crypto.go), so identical plaintexts
// never produce identical ciphertext -- a SQL GROUP BY on the raw column
// would never find these duplicates; decrypting in application code is the
// only way to compare real content. Used by brain_diagnostics. Result is
// cached for duplicateFactsCacheTTL, since this is a full-table decrypt.
func (a *App) CountDuplicateFacts(ctx context.Context) (int, error) {
	if a.db == nil {
		return 0, fmt.Errorf("database not initialized")
	}

	a.duplicateFactsCacheMu.Lock()
	if !a.duplicateFactsCacheTime.IsZero() && time.Since(a.duplicateFactsCacheTime) < duplicateFactsCacheTTL {
		cached := a.duplicateFactsCacheVal
		a.duplicateFactsCacheMu.Unlock()
		return cached, nil
	}
	a.duplicateFactsCacheMu.Unlock()

	rows, err := a.db.QueryContext(ctx, "SELECT project, fact, is_encrypted FROM memory_store")
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	seen := make(map[string]bool)
	duplicates := 0
	for rows.Next() {
		var project, fact string
		var isEncrypted bool
		if err := rows.Scan(&project, &fact, &isEncrypted); err != nil {
			continue
		}
		fact = a.decryptTrackingFailures(fact, isEncrypted)
		key := project + "\x00" + fact
		if seen[key] {
			duplicates++
		}
		seen[key] = true
	}

	a.duplicateFactsCacheMu.Lock()
	a.duplicateFactsCacheVal = duplicates
	a.duplicateFactsCacheTime = time.Now()
	a.duplicateFactsCacheMu.Unlock()

	return duplicates, nil
}

// ClearAllMemories deletes all facts from the SQLite memory store without affecting the encryption key.
func (a *App) ClearAllMemories(ctx context.Context) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if _, err := a.db.ExecContext(ctx, "DELETE FROM memory_store"); err != nil {
		return err
	}
	_, err := a.db.ExecContext(ctx, "DELETE FROM memory_index")
	return err
}

// ClearProjectMemories deletes all facts for a specific project without affecting the encryption key.
func (a *App) ClearProjectMemories(ctx context.Context, project string) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if _, err := a.db.ExecContext(ctx, "DELETE FROM memory_store WHERE project = ?", project); err != nil {
		return err
	}
	_, err := a.db.ExecContext(ctx, "DELETE FROM memory_index WHERE project = ?", project)
	return err
}

// SearchMemoryByTime performs Temporal RAG, filtering records within a
// specific time window. query is required (security-audit finding C3): an
// empty query used to skip the relevance filter entirely, so an empty
// query plus a wide time range decrypted and returned the project's whole
// history in one call -- a DoS (decrypting every matching row) and an
// exfiltration shortcut at once. The row scan itself is also bounded by
// maintenanceMaxResults, same cap search_memory already respects, instead
// of decrypting an unbounded number of rows before ever checking relevance.
func (a *App) SearchMemoryByTime(ctx context.Context, project, query, startTime, endTime string) ([]string, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("query is required")
	}
	if project == "" {
		project = "default"
	}

	rows, err := a.db.QueryContext(ctx, "SELECT fact, is_encrypted FROM memory_store WHERE project = ? AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) AND created_at >= ? AND created_at <= ? ORDER BY created_at ASC", project, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []string
	terms := strings.Fields(strings.ToLower(query))

	for rows.Next() {
		if len(results) >= a.maintenanceMaxResults {
			break
		}
		var fact string
		var isEncrypted bool
		if err := rows.Scan(&fact, &isEncrypted); err != nil {
			continue
		}

		fact = a.decryptTrackingFailures(fact, isEncrypted)

		factLower := strings.ToLower(fact)
		score := 0
		for _, term := range terms {
			if strings.Contains(factLower, term) {
				score++
			}
		}
		if score == 0 {
			continue
		}
		results = append(results, fact)
	}
	return results, nil
}

// CondenseMemory implements Memory Distillation. It deletes a list of old facts and inserts a new golden record, using a transaction.
func (a *App) CondenseMemory(ctx context.Context, project, condensedFact string, factsToDelete []string) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	condensedFact = strings.TrimSpace(condensedFact)

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// Rollback is a no-op after a successful Commit (security-audit finding
	// M5) -- without this, a panic or an early error return before Commit
	// left the transaction open, leaking it and holding SQLite's write lock
	// until something eventually timed out.
	defer func() { _ = tx.Rollback() }()

	// Delete old facts. Fetching and decrypting the project's facts ONCE
	// before the loop (security-audit finding H4) instead of once per
	// entry in factsToDelete -- the original loop re-ran the same SELECT
	// and re-decrypted every row in the project for every fact to delete,
	// O(M*N) in the number of facts to delete times the project's size.
	// Building a plaintext->ids map up front and doing map lookups in the
	// loop is O(M+N): one full scan/decrypt, then constant-time lookups.
	rows, err := tx.QueryContext(ctx, "SELECT id, fact, is_encrypted FROM memory_store WHERE project = ?", project)
	if err != nil {
		return fmt.Errorf("fetch project facts for condense: %w", err)
	}
	idsByFact := make(map[string][]int)
	for rows.Next() {
		var id int
		var fact string
		var isEncrypted bool
		if err := rows.Scan(&id, &fact, &isEncrypted); err == nil {
			fact = a.decryptTrackingFailures(fact, isEncrypted)
			idsByFact[fact] = append(idsByFact[fact], id)
		}
	}
	_ = rows.Close()

	for _, oldFact := range factsToDelete {
		oldFact = strings.TrimSpace(oldFact)
		if oldFact == "" {
			continue
		}
		for _, id := range idsByFact[oldFact] {
			if _, err := tx.ExecContext(ctx, "DELETE FROM memory_store WHERE id = ?", id); err != nil {
				log.DefaultLogger.Warn("condense_memory: failed to delete superseded fact", "id", id, "error", err)
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM memory_index WHERE memory_id = ?", id); err != nil {
				log.DefaultLogger.Warn("condense_memory: failed to delete superseded fact's index entry", "id", id, "error", err)
			}
		}
	}

	// Insert new Golden Record
	storedValue, isEncrypted, err := a.encodeForStorage(condensedFact)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("encryption failed for condensed fact: %w", err)
	}

	result, err := tx.ExecContext(ctx, "INSERT INTO memory_store (project, fact, is_encrypted) VALUES (?, ?, ?)", project, storedValue, isEncrypted)
	if err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Index the golden record's real plaintext -- after commit, same
	// pattern as StoreMemory (a missing index entry here just means this
	// one fact falls back to a full-scan match until the next startup's
	// backfill, never a lost write).
	if memoryID, idErr := result.LastInsertId(); idErr == nil {
		a.indexFact(ctx, memoryID, project, condensedFact)
	}
	return nil
}

// MemoryRecord is one decrypted fact plus its structured metadata, for the
// Brain Hub UI's fact list (badges) and the pending-suggestions queue --
// SearchMemory/UpsertMemory etc. keep returning plain []string for existing
// callers/tests; this is additive, used only by the new metadata-aware
// listing paths below.
type MemoryRecord struct {
	ID         int64      `json:"id"`
	Fact       string     `json:"fact"`
	Type       string     `json:"type,omitempty"`
	Tags       string     `json:"tags,omitempty"`
	Service    string     `json:"service,omitempty"`
	Namespace  string     `json:"namespace,omitempty"`
	Source     string     `json:"source,omitempty"`
	Confidence float64    `json:"confidence,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  string     `json:"createdAt,omitempty"`
	// PIIDetected flags a fact whose text matched one of detectPII's
	// heuristic patterns (email, CPF, IP, card-shaped digit run, long
	// token) -- a signal for human review, never a block on the write.
	PIIDetected bool `json:"piiDetected,omitempty"`
	// Author names the person who curated/confirmed this fact -- see
	// MemoryMetadata.Author.
	Author string `json:"author,omitempty"`
}

// scanMemoryRecord decrypts one memory_store row into a MemoryRecord --
// shared by ListFactsWithMetadata, ListPendingFacts, and RetrieveRunbook so
// none of them can drift on which columns get scanned/decrypted. Every
// caller's SELECT must list columns in EXACTLY this order:
// id, fact, is_encrypted, type, tags, service, namespace, source,
// confidence, expires_at, status, created_at, pii_detected, author.
func (a *App) scanMemoryRecord(rows *sql.Rows) (MemoryRecord, error) {
	var r MemoryRecord
	var isEncrypted bool
	var typ, tags, service, namespace, source, createdAt, author sql.NullString
	var confidence sql.NullFloat64
	var expiresAt sql.NullString
	if err := rows.Scan(&r.ID, &r.Fact, &isEncrypted, &typ, &tags, &service, &namespace, &source, &confidence, &expiresAt, &r.Status, &createdAt, &r.PIIDetected, &author); err != nil {
		return r, err
	}
	r.Fact = a.decryptTrackingFailures(r.Fact, isEncrypted)
	r.Type, r.Tags, r.Service, r.Namespace, r.Source, r.CreatedAt, r.Author = typ.String, tags.String, service.String, namespace.String, source.String, createdAt.String, author.String
	if confidence.Valid {
		r.Confidence = confidence.Float64
	}
	if expiresAt.Valid {
		if t, err := time.Parse("2006-01-02 15:04:05", expiresAt.String); err == nil {
			r.ExpiresAt = &t
		}
	}
	return r, nil
}

// ListFactsWithMetadata returns every approved, non-expired fact for a
// project with its structured metadata -- the metadata-aware counterpart to
// SearchMemory(ctx, project, "", false), used by handleFacts for the Brain
// Hub UI's per-project fact list (type/service/tags badges).
func (a *App) ListFactsWithMetadata(ctx context.Context, project string) ([]MemoryRecord, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, fact, is_encrypted, type, tags, service, namespace, source, confidence, expires_at, status, created_at, pii_detected, author
		 FROM memory_store
		 WHERE project = ? AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at DESC`, project)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []MemoryRecord
	for rows.Next() {
		r, err := a.scanMemoryRecord(rows)
		if err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

// SuggestMemory is what an LLM should call for its own inferred
// observations (not something the user explicitly asked to save) -- it
// lands with status="pending" and source="llm-suggested", invisible to
// normal search until an admin approves it from the Brain Hub's Pending
// Suggestions queue (see ListPendingFacts/ApprovePendingFact/
// RejectPendingFact). Explicit "remember X"/"save this" requests keep going
// through store_memory/upsert_memory and bypass this queue entirely.
func (a *App) SuggestMemory(ctx context.Context, project, fact string) error {
	return a.storeMemoryRecord(ctx, project, fact, &MemoryMetadata{Source: "llm-suggested", Status: "pending"})
}

// ListPendingFacts returns every pending (not yet approved/rejected)
// suggestion for a project, oldest first -- for the Brain Hub's Pending
// Suggestions card.
func (a *App) ListPendingFacts(ctx context.Context, project string) ([]MemoryRecord, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, fact, is_encrypted, type, tags, service, namespace, source, confidence, expires_at, status, created_at, pii_detected, author
		 FROM memory_store
		 WHERE project = ? AND status = 'pending'
		 ORDER BY created_at ASC`, project)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []MemoryRecord
	for rows.Next() {
		r, err := a.scanMemoryRecord(rows)
		if err != nil {
			continue
		}
		records = append(records, r)
	}
	return records, nil
}

// RetrieveRunbook returns approved, non-expired facts of type="runbook" for
// a project, optionally filtered/ranked by query -- the type='runbook' AND
// status='approved' restriction is the whole point (per the agent-ai tools
// roadmap): keeps this to curated, reviewed procedures instead of any old
// chat observation that happened to get remembered under a different type,
// reducing the chance of an assistant treating stale/unreliable guidance as
// an authoritative runbook. A runbook fact reaches status='approved' the
// same way any suggested fact does -- store/upsert_memory with type=
// "runbook" for an explicit, already-trusted entry, or suggest_memory (then
// the existing ApprovePendingFact flow) if it should go through human
// review first; no new review mechanism was added; type="runbook" plus the
// existing status column already covers it entirely.
func (a *App) RetrieveRunbook(ctx context.Context, project, query string) ([]MemoryRecord, error) {
	if a.db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	if project == "" {
		project = "default"
	}
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, fact, is_encrypted, type, tags, service, namespace, source, confidence, expires_at, status, created_at, pii_detected, author
		 FROM memory_store
		 WHERE project = ? AND type = 'runbook' AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at DESC`, project)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var all []MemoryRecord
	for rows.Next() {
		r, err := a.scanMemoryRecord(rows)
		if err != nil {
			continue
		}
		all = append(all, r)
	}

	if query == "" {
		if len(all) > a.maintenanceMaxResults {
			all = all[:a.maintenanceMaxResults]
		}
		return all, nil
	}

	// Filtering/ranking happens here, in Go, against the already-decrypted
	// fact text -- not a SQL LIKE on the fact column, which would silently
	// never match once at-rest encryption is on (the stored value is
	// ciphertext). Reuses scoreFact so runbook relevance ranking can never
	// silently drift from SearchMemory's own lexical ranking.
	terms := strings.Fields(strings.ToLower(query))
	type scoredRunbook struct {
		record MemoryRecord
		score  int
	}
	var scored []scoredRunbook
	for _, r := range all {
		score, matchedTerms := scoreFact(r.Fact+" "+r.Tags, query, terms)
		if !a.passesOverlapThreshold(matchedTerms, len(terms)) {
			continue
		}
		if score > 0 {
			scored = append(scored, scoredRunbook{record: r, score: score})
		}
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].score > scored[j].score })

	var out []MemoryRecord
	for i, s := range scored {
		if i >= a.maintenanceMaxResults {
			break
		}
		out = append(out, s.record)
	}
	if len(out) == 0 {
		// Fallback, same shape as SearchMemory's own no-match fallback: a
		// few of the most recent runbooks are more useful than a flat
		// empty result when nothing scored above zero.
		if len(all) > 10 {
			return all[:10], nil
		}
		return all, nil
	}
	return out, nil
}

// ApprovePendingFact promotes a pending suggestion to a real, searchable
// memory -- it was already indexed (indexFact runs on every insert
// regardless of status), so approving is just a status flip, no re-indexing
// needed.
func (a *App) ApprovePendingFact(ctx context.Context, id int64) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	res, err := a.db.ExecContext(ctx, "UPDATE memory_store SET status = 'approved' WHERE id = ? AND status = 'pending'", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no pending suggestion found with id %d", id)
	}
	return nil
}

// RejectPendingFact discards a pending suggestion permanently -- a rejected
// suggestion serves no purpose kept around, unlike a real memory (which is
// only ever removed via the explicit delete_memory/Clear Data paths).
func (a *App) RejectPendingFact(ctx context.Context, id int64) error {
	if a.db == nil {
		return fmt.Errorf("database not initialized")
	}
	res, err := a.db.ExecContext(ctx, "DELETE FROM memory_store WHERE id = ? AND status = 'pending'", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no pending suggestion found with id %d", id)
	}
	a.removeFactFromIndex(ctx, id)
	return nil
}
