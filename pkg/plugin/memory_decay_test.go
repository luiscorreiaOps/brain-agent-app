package plugin

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestInitDB_AddsLastAccessedColumnOnPreExistingTable(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-last-accessed-migration-test-*")
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
		t.Fatalf("InitDB on a pre-existing table missing last_accessed failed: %v", err)
	}

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('memory_store') WHERE name = 'last_accessed'").Scan(&count); err != nil {
		t.Fatalf("query table info: %v", err)
	}
	if count != 1 {
		t.Error("last_accessed column was not added by the migration")
	}
}

func TestMemoryDecayWeight_ZeroAgeIsFullWeight(t *testing.T) {
	t.Parallel()

	weight := memoryDecayWeight(sql.NullFloat64{Float64: 0, Valid: true})
	if weight != 1.0 {
		t.Errorf("weight = %v, want 1.0 for zero age", weight)
	}
}

func TestMemoryDecayWeight_OldAgeHitsFloor(t *testing.T) {
	t.Parallel()

	// Far beyond several half-lives (14 days each) -- must clamp at the
	// floor, never keep decaying toward (or past) zero.
	weight := memoryDecayWeight(sql.NullFloat64{Float64: 365, Valid: true})
	if weight != memoryDecayFloor {
		t.Errorf("weight = %v, want the floor %v for a year-old reference", weight, memoryDecayFloor)
	}
}

func TestMemoryDecayWeight_HalfLifeHalvesWeight(t *testing.T) {
	t.Parallel()

	weight := memoryDecayWeight(sql.NullFloat64{Float64: memoryDecayHalfLifeDays, Valid: true})
	if weight < 0.49 || weight > 0.51 {
		t.Errorf("weight = %v, want ~0.5 at exactly one half-life", weight)
	}
}

func TestMemoryDecayWeight_NullOrNonPositiveAgeReturnsNoDecay(t *testing.T) {
	t.Parallel()

	if w := memoryDecayWeight(sql.NullFloat64{}); w != 1.0 {
		t.Errorf("weight = %v, want 1.0 for a NULL age", w)
	}
	if w := memoryDecayWeight(sql.NullFloat64{Float64: -1, Valid: true}); w != 1.0 {
		t.Errorf("weight = %v, want 1.0 for a negative age (clock skew)", w)
	}
}

func TestSearchMemory_RecentlyAccessedFactOutranksStaleEquallyScoredFact(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	// Two facts, each containing exactly one of the query's terms once --
	// same raw lexical score. Without decay, ranking would tie-break
	// arbitrarily (or by insertion order); with decay, the one recently
	// confirmed relevant (last_accessed just touched) must outrank the one
	// that hasn't been touched since it was created a long time ago.
	if err := app.StoreMemory(ctx, "decay-project", "stale entry about the router config"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "decay-project", "fresh entry about the router config"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	if _, err := app.db.Exec("UPDATE memory_store SET created_at = datetime('now', '-90 days') WHERE fact LIKE '%stale entry%'"); err != nil {
		t.Fatalf("backdating stale fact failed: %v", err)
	}
	if _, err := app.db.Exec("UPDATE memory_store SET created_at = datetime('now', '-90 days'), last_accessed = datetime('now') WHERE fact LIKE '%fresh entry%'"); err != nil {
		t.Fatalf("setting last_accessed on the fresh fact failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "decay-project", "router config", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %v, want both facts matched", results)
	}
	if results[0] != "fresh entry about the router config" {
		t.Errorf("results[0] = %q, want the recently-accessed fact ranked first despite an identical lexical score", results[0])
	}
}

func TestSearchMemory_TouchesLastAccessedOnMatch(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "touch-project", "a fact about the payment gateway"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	var before sql.NullString
	if err := app.db.QueryRow("SELECT last_accessed FROM memory_store WHERE project = 'touch-project'").Scan(&before); err != nil {
		t.Fatalf("query before: %v", err)
	}
	if before.Valid {
		t.Fatalf("last_accessed should be unset before any search, got %q", before.String)
	}

	if _, err := app.SearchMemory(ctx, "touch-project", "payment gateway", true); err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}

	var after sql.NullString
	if err := app.db.QueryRow("SELECT last_accessed FROM memory_store WHERE project = 'touch-project'").Scan(&after); err != nil {
		t.Fatalf("query after: %v", err)
	}
	if !after.Valid {
		t.Error("expected last_accessed to be set after a matching search")
	}
}
