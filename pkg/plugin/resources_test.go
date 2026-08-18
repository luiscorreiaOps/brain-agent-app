package plugin

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

func newTestDB(t *testing.T) *App {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "brain-agent-resources-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	app := &App{logger: log.NewNullLogger(), maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	return app
}

func callSearchMemory(t *testing.T, app *App, settings Settings, project, query string) string {
	t.Helper()
	args, err := json.Marshal(map[string]string{"query": query, "project": project})
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	params, err := json.Marshal(map[string]any{"name": "search_memory", "arguments": json.RawMessage(args)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, err := app.handleToolsCall(context.Background(), params, settings)
	if err != nil {
		t.Fatalf("handleToolsCall failed: %v", err)
	}
	return result
}

func TestSearchMemoryTool_SemanticSearchDisabled_ReturnsRecentRegardlessOfMatch(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "sre-team", "unrelated fact about the CPU"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	disabled := false
	settings := Settings{SemanticSearchEnabled: &disabled}

	// Query term matches nothing in the stored fact -- with semantic search
	// off this must still return the fact (recency-based), not "no matches".
	result := callSearchMemory(t, app, settings, "sre-team", "totally unrelated query terms")
	if strings.Contains(result, "no matches found") {
		t.Errorf("result = %q, want the recent fact returned even without a term match (semantic search disabled)", result)
	}
	if !strings.Contains(result, "unrelated fact about the CPU") {
		t.Errorf("result = %q, want it to contain the stored fact", result)
	}
}

func TestSearchMemoryTool_StrictTenancyDisabled_FallsBackToDefaultProject(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "default", "global runbook fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	notStrict := false
	settings := Settings{StrictTenancyEnabled: &notStrict}

	// "some-empty-project" has nothing of its own -- with strict tenancy
	// off, it should still surface the "default" project's fact.
	result := callSearchMemory(t, app, settings, "some-empty-project", "runbook")
	if !strings.Contains(result, "global runbook fact") {
		t.Errorf("result = %q, want the default-project fact to be found via fallback", result)
	}
}

func TestSearchMemoryTool_StrictTenancyEnabledByDefault_NoCrossProjectLeak(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "default", "global runbook fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	// Zero-value Settings -- StrictTenancyEnabled is nil, which must default
	// to strict (true), i.e. no fallback to "default".
	result := callSearchMemory(t, app, Settings{}, "some-empty-project", "runbook")
	if strings.Contains(result, "global runbook fact") {
		t.Errorf("result = %q, want no cross-project leakage when Strict Tenancy is at its default (on)", result)
	}
}
