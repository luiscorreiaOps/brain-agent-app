package plugin

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseStorageAndSearch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }() // clean up

	app := &App{maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	ctx := context.Background()

	// Test storing memory
	err = app.StoreMemory(ctx, "sre-team", "The database crashes when memory hits 90%")
	if err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	err = app.StoreMemory(ctx, "sre-team", "Another runbook fact about CPU limits")
	if err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	err = app.StoreMemory(ctx, "default", "Global setting enabled")
	if err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	// Test searching memory (match)
	results, err := app.SearchMemory(ctx, "sre-team", "database crashes", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 match, got %d", len(results))
	} else if results[0] != "The database crashes when memory hits 90%" {
		t.Errorf("Unexpected search result: %v", results[0])
	}

	// Test searching memory (fallback to recent for empty/no-match)
	fallback, err := app.SearchMemory(ctx, "sre-team", "xyz non existent", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(fallback) != 2 { // Should return all 2 facts for sre-team since it falls back
		t.Errorf("Expected 2 fallback results, got %d", len(fallback))
	}

	// Verify database file was created
	dbPath := filepath.Join(tempDir, "brain-agent.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("Database file was not created at %s", dbPath)
	}
}

// Security-audit finding C3: an empty query used to skip the relevance
// filter entirely, so an empty query plus a wide time range returned every
// approved fact in the project's whole history, decrypted, in one call --
// a DoS (decrypting every matching row) and an exfiltration shortcut at
// once. query is now required.
// Security-audit finding M4: an old-scheme (pre-project-scoped) HMAC row
// can never be "upgraded" in place (HMACs are one-way) -- InitDB must
// clear it and let the backfill recreate it under the new scheme.
// Security-audit finding L4: startHealthMaintenance used to start a bare
// goroutine with no cancellation mechanism at all -- calling InitDB again
// (a real re-init, e.g. after handleCryptoReset, or in this test suite's
// case, every single test calling it independently) piled up one more
// orphaned goroutine each time, forever. Repeated InitDB calls must leave
// exactly one maintenance goroutine reachable via StopHealthMaintenance,
// and stopping it (or calling Dispose, which now calls this too) must
// never panic regardless of how many times InitDB already ran.
func TestStartHealthMaintenance_RepeatedInitDoesNotLeakOrPanic(t *testing.T) {
	tempDir := t.TempDir()
	app := &App{maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	for i := 0; i < 5; i++ {
		if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
			t.Fatalf("InitDB call %d failed: %v", i, err)
		}
	}
	// Must be safe to call, and safe to call again (no double-close panic).
	app.StopHealthMaintenance()
	app.StopHealthMaintenance()
}

func TestInitDB_MigratesOldHMACSchemeRows(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-migration-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	app := &App{maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	ctx := context.Background()
	if err := app.StoreMemory(ctx, "sre-team", "a fact indexed under the current scheme"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	// Simulate a pre-migration row: same shape indexFact would have
	// written before project-scoping, tagged with the old scheme.
	if _, err := app.db.Exec("INSERT INTO memory_index (memory_id, project, token_hmac, hmac_scheme) VALUES (999, 'sre-team', 'stale-old-scheme-hash', 1)"); err != nil {
		t.Fatalf("seed old-scheme row: %v", err)
	}

	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("second InitDB (simulating a restart) failed: %v", err)
	}

	var remaining int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_index WHERE hmac_scheme < ?", currentHMACScheme).Scan(&remaining); err != nil {
		t.Fatalf("count old-scheme rows: %v", err)
	}
	if remaining != 0 {
		t.Errorf("found %d rows still on an old HMAC scheme after a restart, want 0", remaining)
	}

	var currentCount int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_index WHERE hmac_scheme = ?", currentHMACScheme).Scan(&currentCount); err != nil {
		t.Fatalf("count current-scheme rows: %v", err)
	}
	if currentCount == 0 {
		t.Error("expected the backfill to have reindexed at least the real fact under the current scheme")
	}
}

// Security-audit finding L5: queries filter by (project, status,
// expires_at) together, but the only index available was on project alone.
func TestInitDB_CreatesCompositeIndexOnMemoryStore(t *testing.T) {
	app := newTestDB(t)

	var name string
	err := app.db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_memory_project_status_expires'").Scan(&name)
	if err != nil {
		t.Fatalf("composite index idx_memory_project_status_expires not found: %v", err)
	}
}

// Regression test for a real ordering bug caught while implementing L5:
// the composite index was first added inside createTableSQL, which runs
// BEFORE the ALTER TABLE migrations that add status/expires_at to an
// install that predates those columns -- "CREATE INDEX ... (project,
// status, expires_at)" against a table missing those columns errors with
// "no such column", which would have broken InitDB entirely for exactly
// the upgrading installs the index is meant to help. Simulates that
// upgrade path directly: a memory_store table with neither column yet.
func TestInitDB_CreatesCompositeIndexOnPreExistingTableMissingColumns(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-index-migration-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "brain-agent.db")
	seedDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open seed db: %v", err)
	}
	if _, err := seedDB.Exec(`CREATE TABLE memory_store (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project TEXT NOT NULL,
		fact TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("seed old-schema memory_store: %v", err)
	}
	if err := seedDB.Close(); err != nil {
		t.Fatalf("close seed db: %v", err)
	}

	app := &App{maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB on a pre-existing table missing status/expires_at failed: %v", err)
	}

	var name string
	if err := app.db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_memory_project_status_expires'").Scan(&name); err != nil {
		t.Errorf("composite index was not created after the migration: %v", err)
	}
}

func TestSearchMemoryByTime_RejectsEmptyQuery(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "sre-team", "a fact that should not be returned by an empty query"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	_, err := app.SearchMemoryByTime(ctx, "sre-team", "", "2020-01-01", "2030-01-01")
	if err == nil {
		t.Fatal("SearchMemoryByTime(query=\"\") should return an error, got nil")
	}
}

func TestSearchMemoryByTime_BoundedByMaintenanceMaxResults(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	for i := 0; i < app.maintenanceMaxResults+10; i++ {
		if err := app.StoreMemory(ctx, "sre-team", "repeated matching fact about outages"); err != nil {
			t.Fatalf("StoreMemory failed: %v", err)
		}
	}

	results, err := app.SearchMemoryByTime(ctx, "sre-team", "outages", "2020-01-01", "2030-01-01")
	if err != nil {
		t.Fatalf("SearchMemoryByTime failed: %v", err)
	}
	if len(results) > app.maintenanceMaxResults {
		t.Errorf("len(results) = %d, want at most maintenanceMaxResults (%d)", len(results), app.maintenanceMaxResults)
	}
}
