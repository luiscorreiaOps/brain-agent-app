package plugin

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInitDB_AddsAuthorColumnOnPreExistingTable regression-tests the
// author migration the same way TestInitDB_CreatesCompositeIndexOnPre...
// already does for the composite index: a memory_store table predating
// this column must still get it added on the next InitDB call, not error
// out or silently skip it.
func TestInitDB_AddsAuthorColumnOnPreExistingTable(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-author-migration-test-*")
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
		t.Fatalf("InitDB on a pre-existing table missing author failed: %v", err)
	}

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('memory_store') WHERE name = 'author'").Scan(&count); err != nil {
		t.Fatalf("query table info: %v", err)
	}
	if count != 1 {
		t.Error("author column was not added by the migration")
	}
}

func TestRetrieveRunbook_OnlyReturnsApprovedRunbookType(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	// A runbook (should be returned), a non-runbook fact (must NOT be
	// returned even though it's approved), and a pending runbook (must NOT
	// be returned until approved) -- exercises the whole point of
	// RetrieveRunbook's restriction.
	if err := app.StoreMemoryWithMetadata(ctx, "sre-team", "Restart the pod to clear the stuck connection", &MemoryMetadata{Type: "runbook", Author: "luis"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "sre-team", "Just a regular observation, not a runbook"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.storeMemoryRecord(ctx, "sre-team", "Draft runbook awaiting review", &MemoryMetadata{Type: "runbook", Status: "pending"}); err != nil {
		t.Fatalf("storeMemoryRecord failed: %v", err)
	}

	records, err := app.RetrieveRunbook(ctx, "sre-team", "")
	if err != nil {
		t.Fatalf("RetrieveRunbook failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 runbook, got %d: %+v", len(records), records)
	}
	if records[0].Fact != "Restart the pod to clear the stuck connection" {
		t.Errorf("unexpected runbook fact: %q", records[0].Fact)
	}
	if records[0].Author != "luis" {
		t.Errorf("author = %q, want %q", records[0].Author, "luis")
	}
}

func TestRetrieveRunbook_FiltersByQueryRelevance(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemoryWithMetadata(ctx, "sre-team", "Database connection pool exhaustion: restart the pod", &MemoryMetadata{Type: "runbook"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}
	if err := app.StoreMemoryWithMetadata(ctx, "sre-team", "Disk cleanup procedure for the logging volume", &MemoryMetadata{Type: "runbook"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}

	records, err := app.RetrieveRunbook(ctx, "sre-team", "connection pool exhaustion")
	if err != nil {
		t.Fatalf("RetrieveRunbook failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly 1 matching runbook, got %d: %+v", len(records), records)
	}
	if records[0].Fact != "Database connection pool exhaustion: restart the pod" {
		t.Errorf("unexpected runbook returned for the query: %q", records[0].Fact)
	}
}

func TestRetrieveRunbook_EmptyWhenNoneExist(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "sre-team", "A regular fact, no runbooks stored"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	records, err := app.RetrieveRunbook(ctx, "sre-team", "")
	if err != nil {
		t.Fatalf("RetrieveRunbook failed: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected no runbooks, got %d: %+v", len(records), records)
	}
}

func TestRetrieveRunbookTool_DispatchesThroughHandleToolsCall(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemoryWithMetadata(ctx, "sre-team", "Restart the pod to clear the stuck connection", &MemoryMetadata{Type: "runbook", Author: "luis"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}

	args, err := json.Marshal(map[string]string{"project": "sre-team"})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	params, err := json.Marshal(map[string]any{"name": "retrieve_runbook", "arguments": json.RawMessage(args)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, err := app.handleToolsCall(ctx, params, Settings{})
	if err != nil {
		t.Fatalf("handleToolsCall failed: %v", err)
	}
	if !strings.Contains(result, "Restart the pod to clear the stuck connection") {
		t.Errorf("result = %q, want it to contain the stored runbook", result)
	}
	if !strings.Contains(result, "author: luis") {
		t.Errorf("result = %q, want it to mention the author", result)
	}
}

func TestRetrieveRunbookTool_NoneFoundReportsExplicitly(t *testing.T) {
	app := newTestDB(t)

	params, err := json.Marshal(map[string]any{"name": "retrieve_runbook", "arguments": json.RawMessage(`{"project":"sre-team"}`)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}

	result, err := app.handleToolsCall(context.Background(), params, Settings{})
	if err != nil {
		t.Fatalf("handleToolsCall failed: %v", err)
	}
	if !strings.Contains(result, "No approved runbooks found") {
		t.Errorf("result = %q, want an explicit no-runbooks-found message", result)
	}
}

func TestRetrieveRunbook_ScopedByProject(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemoryWithMetadata(ctx, "team-a", "Team A's runbook", &MemoryMetadata{Type: "runbook"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}
	if err := app.StoreMemoryWithMetadata(ctx, "team-b", "Team B's runbook", &MemoryMetadata{Type: "runbook"}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}

	records, err := app.RetrieveRunbook(ctx, "team-a", "")
	if err != nil {
		t.Fatalf("RetrieveRunbook failed: %v", err)
	}
	if len(records) != 1 || records[0].Fact != "Team A's runbook" {
		t.Errorf("expected only team-a's runbook, got %+v", records)
	}
}
