package plugin

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// ============================================================================
// Searchable-encryption token index -- why this exists instead of FTS5
// ============================================================================
// SearchMemory's original design decrypts every fact in a project and scans
// it in application code -- correct, but O(n) per search regardless of
// match, and it doesn't scale the way a real text index would. The obvious
// fix (SQLite FTS5, which modernc.org/sqlite supports) was deliberately NOT
// taken: FTS5 needs to index the actual words to be useful, and this
// plugin's core promise is "every fact is encrypted on disk, unconditionally"
// (see db.go/BrainHub.tsx). Indexing plaintext defeats that promise the
// moment anyone with file access to the .db reads the index directly --
// AES-GCM ciphertext is designed to look random, but an FTS5 index built
// from the same words is not.
//
// This is the middle ground: index HMAC-SHA256(token) instead of the token
// itself, keyed with brain_hmac.key -- a SEPARATE key from brain_aes.key on
// purpose (key separation: compromising one key must not help decrypt or
// re-derive the other). A search recomputes the same HMACs for its own
// query terms and looks up matching memory_ids BEFORE ever calling Decrypt,
// so only real candidates get decrypted, and the index itself never
// contains anything an attacker with DB-file-only access could read back
// into words without also holding brain_hmac.key.
//
// Residual, disclosed limitation (this is searchable encryption, not free
// lunch): someone with DB access can see that two facts share a token
// (same HMAC value appearing in two rows) without knowing what the token
// is -- a real but narrow access-pattern leak. If brain_hmac.key itself
// leaks AND the vocabulary is small, an offline dictionary attack (HMAC
// every guessed word, compare) becomes feasible -- exactly why this key is
// never derived from or stored alongside brain_aes.key.

// InitSearchIndexKey loads or generates the HMAC key backing the token
// index, and ensures the memory_index table exists. Called from InitDB,
// same lifecycle as InitCrypto's AES key.
func (a *App) InitSearchIndexKey(dataDir string) error {
	// Org-suffixed for every org but the default one, same reasoning as
	// InitCrypto's brain_aes.key (see orgSuffixedName, H8's remaining gap).
	keyPath := filepath.Join(dataDir, fmt.Sprintf("%s.key", orgSuffixedName("brain_hmac", a.orgID)))

	if _, err := os.Stat(keyPath); err == nil {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return fmt.Errorf("FATAL: existing HMAC index key file found but could not be read: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("FATAL: existing HMAC index key is corrupted (invalid length: %d bytes)", len(key))
		}
		a.hmacKey = key
		log.DefaultLogger.Info("Loaded existing HMAC key for the search token index")
		return nil
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("failed to generate HMAC index key: %w", err)
	}
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to securely create HMAC index key file (prevented overwrite): %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("failed to write HMAC index key: %w", err)
	}
	a.hmacKey = key
	log.DefaultLogger.Info("Generated new HMAC key for the search token index", "path", keyPath)
	return nil
}

// stopwords: closed-class function words only (PT-BR + EN) -- deliberately
// small and conservative. A word wrongly treated as a stopword just means
// it's ignored for indexing/search, silently hurting recall for that one
// term; over-including here is worse than under-including. Never add a
// technical term here (see db.go's TF-IDF-lite scoring, which has the same
// principle for its own exact-phrase bonus).
var stopwords = map[string]bool{
	"a": true, "as": true, "o": true, "os": true, "um": true, "uma": true,
	"de": true, "do": true, "da": true, "dos": true, "das": true,
	"em": true, "no": true, "na": true, "nos": true, "nas": true,
	"e": true, "ou": true, "que": true, "com": true, "para": true, "por": true,
	"se": true, "é": true, "foi": true, "ser": true, "esta": true, "este": true,
	"the": true, "an": true, "of": true, "in": true, "on": true, "at": true,
	"and": true, "or": true, "to": true, "for": true, "is": true, "are": true,
	"was": true, "were": true, "with": true, "this": true, "that": true,
}

// stripAccents removes combining diacritical marks (á->a, ç->c, ã->a, ...)
// via Unicode NFD decomposition + Mn-class filtering -- so "não" and "nao",
// or "código" and "codigo", index and search identically.
func stripAccents(s string) string {
	t := transform.Chain(norm.NFD, runes.Remove(runes.Predicate(func(r rune) bool {
		return unicode.Is(unicode.Mn, r)
	})), norm.NFC)
	result, _, err := transform.String(t, s)
	if err != nil {
		return s
	}
	return result
}

// tokenize normalizes text into indexable/searchable tokens: lowercase,
// accent-stripped, split on anything that isn't a letter or digit, short
// (<2 chars) and stopword tokens dropped.
func tokenize(text string) []string {
	normalized := stripAccents(strings.ToLower(text))
	fields := strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	tokens := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 2 || stopwords[f] {
			continue
		}
		tokens = append(tokens, f)
	}
	return tokens
}

// hmacToken returns the hex-encoded HMAC-SHA256 of one normalized token,
// keyed with hmacKey and scoped to project. Never called with
// unnormalized text -- always route through tokenize first, so a search
// recomputes byte-identical input for byte-identical output.
//
// project is folded into the HMAC input (security-audit finding M4): the
// same word in two different projects used to produce the identical HMAC
// value, which someone with raw .db file access (no hmac key needed) could
// use to correlate vocabulary across projects that are otherwise meant to
// be isolated -- e.g. noticing "finance-team" and "hr-team" share tokens,
// without knowing what those tokens are. Prefixing project makes each
// project's HMAC space independent even for identical underlying words.
func (a *App) hmacToken(project, token string) (string, error) {
	if len(a.hmacKey) == 0 {
		return "", fmt.Errorf("search index not initialized")
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write([]byte(project))
	mac.Write([]byte{0})
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// currentHMACScheme is stored per-row in memory_index.hmac_scheme so a
// startup migration can tell old (pre-project-scoping) rows from new ones
// and reindex only what's stale -- see db.go's InitDB.
const currentHMACScheme = 2

// indexFact tokenizes a fact's real plaintext and stores one HMAC row per
// unique token in memory_index, linked to memoryID. Called right after a
// successful insert into memory_store -- indexing failure is logged, never
// returned as a write failure (the fact is safely stored either way; a
// missing index entry just means degraded search recall for that one fact,
// same fallback-to-full-scan safety net as an empty index result set).
func (a *App) indexFact(ctx context.Context, memoryID int64, project, plaintextFact string) {
	if a.db == nil {
		return
	}
	tokens := tokenize(plaintextFact)
	seen := make(map[string]bool, len(tokens))
	for _, token := range tokens {
		if seen[token] {
			continue
		}
		seen[token] = true
		h, err := a.hmacToken(project, token)
		if err != nil {
			log.DefaultLogger.Warn("search index: failed to hash token, skipping", "error", err)
			continue
		}
		if _, err := a.db.ExecContext(ctx, "INSERT INTO memory_index (memory_id, project, token_hmac, hmac_scheme) VALUES (?, ?, ?, ?)", memoryID, project, h, currentHMACScheme); err != nil {
			log.DefaultLogger.Warn("search index: failed to insert index row", "error", err)
		}
	}
}

// removeFactFromIndex deletes memory_index rows for one deleted fact.
func (a *App) removeFactFromIndex(ctx context.Context, memoryID int64) {
	if a.db == nil {
		return
	}
	if _, err := a.db.ExecContext(ctx, "DELETE FROM memory_index WHERE memory_id = ?", memoryID); err != nil {
		log.DefaultLogger.Warn("search index: failed to clean up index rows", "error", err, "memory_id", memoryID)
	}
}

// candidateIDsFromIndex looks up which memory_ids in project match ANY
// token of query, via the HMAC index -- no Decrypt call anywhere in this
// function. ok=false means the query had no usable tokens (e.g. it was
// entirely stopwords/punctuation) and the caller should fall back to a
// full project scan instead of treating "no candidates" as "no matches".
func (a *App) candidateIDsFromIndex(ctx context.Context, project, query string) (ids map[int64]bool, ok bool) {
	tokens := tokenize(query)
	if len(tokens) == 0 {
		return nil, false
	}

	ids = make(map[int64]bool)
	for _, token := range tokens {
		h, err := a.hmacToken(project, token)
		if err != nil {
			continue
		}
		rows, err := a.db.QueryContext(ctx, "SELECT DISTINCT memory_id FROM memory_index WHERE project = ? AND token_hmac = ?", project, h)
		if err != nil {
			continue
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err == nil {
				ids[id] = true
			}
		}
		_ = rows.Close()
	}
	return ids, true
}

// backfillSearchIndexIfNeeded populates memory_index for facts written
// before this index existed (or before a key reset invalidated it) --
// otherwise search on pre-existing facts would silently only ever hit the
// full-scan fallback path, since the index has nothing to say about them.
// Safe to call every startup: a no-op once every row already has an index
// entry.
func (a *App) backfillSearchIndexIfNeeded(ctx context.Context) {
	if a.db == nil {
		return
	}
	rows, err := a.db.QueryContext(ctx, `
		SELECT m.id, m.project, m.fact, m.is_encrypted
		FROM memory_store m
		LEFT JOIN memory_index i ON i.memory_id = m.id
		WHERE i.memory_id IS NULL
	`)
	if err != nil {
		log.DefaultLogger.Warn("search index: backfill query failed", "error", err)
		return
	}
	defer func() { _ = rows.Close() }()

	type pending struct {
		id      int64
		project string
		fact    string
	}
	var toIndex []pending
	for rows.Next() {
		var p pending
		var isEncrypted bool
		if err := rows.Scan(&p.id, &p.project, &p.fact, &isEncrypted); err != nil {
			continue
		}
		p.fact = a.decryptTrackingFailures(p.fact, isEncrypted)
		toIndex = append(toIndex, p)
	}

	if len(toIndex) == 0 {
		return
	}
	for _, p := range toIndex {
		a.indexFact(ctx, p.id, p.project, p.fact)
	}
	log.DefaultLogger.Info("search index: backfilled facts written before the index existed", "count", len(toIndex))
}

// encryptedFactByID (base64) fact/is_encrypted/age-in-days for one
// memory_store id -- used to fetch only the candidate rows the index
// already narrowed down to. Excludes pending suggestions and expired facts,
// matching every other search path -- a candidate ID pointing at either now
// simply yields ok=false, which searchViaIndex's loop already treats as
// "skip". ageDays (see memoryDecayAgeDaysExpr) feeds memoryDecayWeight so
// the index path ranks facts with the same recency-of-use signal as the
// other two search paths.
func (a *App) encryptedFactByID(ctx context.Context, id int64) (fact string, isEncrypted bool, ageDays sql.NullFloat64, ok bool) {
	row := a.db.QueryRowContext(ctx, "SELECT fact, is_encrypted, "+memoryDecayAgeDaysExpr+" FROM memory_store WHERE id = ? AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)", id)
	if err := row.Scan(&fact, &isEncrypted, &ageDays); err != nil {
		return "", false, sql.NullFloat64{}, false
	}
	return fact, isEncrypted, ageDays, true
}
