package plugin

import (
	"context"
	"os"
	"testing"
	"time"
)

// withMaintenanceConfig sets app's maintenance fields for the duration of
// one test.
func withMaintenanceConfig(t *testing.T, app *App, maxDbSizeMB, retentionDays, maxResults int, minOverlapRatio float64) {
	t.Helper()
	app.maintenanceMaxDbSizeMB = maxDbSizeMB
	app.maintenanceRetentionDays = retentionDays
	app.maintenanceMaxResults = maxResults
	app.maintenanceMinOverlapRatio = minOverlapRatio
}

func TestSearchMemory_MaxResultsCapsReturnedFacts(t *testing.T) {
	app := newTestDB(t)
	withMaintenanceConfig(t, app, 500, 0, 2, 0)

	ctx := context.Background()
	for _, fact := range []string{"fact one about vault", "fact two about vault", "fact three about vault"} {
		if err := app.StoreMemory(ctx, "capped-project", fact); err != nil {
			t.Fatalf("StoreMemory failed: %v", err)
		}
	}

	results, err := app.SearchMemory(ctx, "capped-project", "vault", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2 (maintenanceMaxResults configured to 2)", len(results))
	}
}

func TestSearchMemory_OverlapThresholdFiltersLowOverlapFacts(t *testing.T) {
	app := newTestDB(t)
	// Require at least 100% of query terms present -- a fact matching only
	// one of two query terms must be filtered out.
	withMaintenanceConfig(t, app, 500, 0, 50, 1.0)

	ctx := context.Background()
	if err := app.StoreMemory(ctx, "overlap-project", "the vault service is healthy"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "overlap-project", "the vault kubernetes pod restarted"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "overlap-project", "vault kubernetes", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly the fact containing BOTH query terms", results)
	}
	if results[0] != "the vault kubernetes pod restarted" {
		t.Errorf("results[0] = %q, want the fully-overlapping fact", results[0])
	}
}

func TestRunMaintenanceOnce_RetentionDeletesOldFacts(t *testing.T) {
	app := newTestDB(t)
	withMaintenanceConfig(t, app, 500, 1, 50, 0)

	ctx := context.Background()
	if err := app.StoreMemory(ctx, "retention-project", "a fresh fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	// Backdate it past the 1-day retention window directly in SQL --
	// StoreMemory always stamps CURRENT_TIMESTAMP, there's no API for this.
	if _, err := app.db.Exec("UPDATE memory_store SET created_at = datetime('now', '-2 days') WHERE project = 'retention-project'"); err != nil {
		t.Fatalf("backdating fact failed: %v", err)
	}

	app.runMaintenanceOnce(currentDBPath(t))

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_store WHERE project = 'retention-project'").Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 (fact is older than the configured 1-day retention window)", count)
	}
}

func TestRunMaintenanceOnce_RetentionDisabledByDefault(t *testing.T) {
	app := newTestDB(t)
	// retentionDays left at 0 -- must never delete anything by age.
	withMaintenanceConfig(t, app, 500, 0, 50, 0)

	ctx := context.Background()
	if err := app.StoreMemory(ctx, "no-retention-project", "an old fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if _, err := app.db.Exec("UPDATE memory_store SET created_at = datetime('now', '-365 days') WHERE project = 'no-retention-project'"); err != nil {
		t.Fatalf("backdating fact failed: %v", err)
	}

	app.runMaintenanceOnce(currentDBPath(t))

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_store WHERE project = 'no-retention-project'").Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (retention disabled -- age must never delete facts)", count)
	}
}

// currentDBPath gives runMaintenanceOnce a real (if throwaway) path for its
// os.Stat size check -- the size-limit branch is irrelevant to these
// retention-focused tests, so any existing file works.
func currentDBPath(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "brain-agent-maintenance-path-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	_ = f.Close()
	return f.Name()
}

func TestPerUserRateLimiter_BlocksAfterLimitThenRecovers(t *testing.T) {
	t.Parallel()
	rl := newPerUserRateLimiter()

	for i := 0; i < 3; i++ {
		if !rl.allow("user-a", 3) {
			t.Fatalf("call %d: allow() = false, want true (within limit)", i+1)
		}
	}
	if rl.allow("user-a", 3) {
		t.Error("4th call: allow() = true, want false (limit exceeded)")
	}
	// A different user has their own independent window.
	if !rl.allow("user-b", 3) {
		t.Error("user-b's first call: allow() = false, want true (separate bucket from user-a)")
	}
}

// Security-audit finding: a truly unlimited default let any caller (a
// Viewer, before the separate MCP RBAC fix, or just a buggy/misbehaving
// integration) hammer store_memory/delete_memory at an unbounded rate.
// limit<=0 now falls back to defaultFloodLimitPerMinute instead of no limit
// at all.
func TestPerUserRateLimiter_ZeroLimitFallsBackToSafeDefault(t *testing.T) {
	t.Parallel()
	rl := newPerUserRateLimiter()
	for i := 0; i < defaultFloodLimitPerMinute; i++ {
		if !rl.allow("user-a", 0) {
			t.Fatalf("call %d: allow() = false, want true (within the default limit of %d)", i+1, defaultFloodLimitPerMinute)
		}
	}
	if rl.allow("user-a", 0) {
		t.Errorf("call %d: allow() = true, want false (exceeds the default limit of %d)", defaultFloodLimitPerMinute+1, defaultFloodLimitPerMinute)
	}
}

func TestPerUserRateLimiter_OldCallsExpireFromWindow(t *testing.T) {
	t.Parallel()
	rl := newPerUserRateLimiter()
	rl.mu.Lock()
	rl.windows["user-a"] = &limiterWindow{times: []time.Time{time.Now().Add(-2 * time.Minute)}, lastUsed: time.Now()}
	rl.mu.Unlock()

	if !rl.allow("user-a", 1) {
		t.Error("allow() = false, want true (the only prior call is outside the 1-minute window)")
	}
}

// Idle per-user windows must eventually be evicted -- otherwise this map
// grows one entry per distinct user for the life of the process with no
// upper bound (the same class of issue fixed for agent-ai-app's limiters).
func TestPerUserRateLimiter_EvictsIdleWindows(t *testing.T) {
	t.Parallel()
	rl := newPerUserRateLimiter()
	rl.mu.Lock()
	rl.windows["idle-user"] = &limiterWindow{
		times:    []time.Time{time.Now()},
		lastUsed: time.Now().Add(-windowIdleEvictAfter - time.Minute),
	}
	rl.mu.Unlock()

	// The sweep only runs every sweepEvery calls -- drive enough calls (for
	// a different, active user) to guarantee at least one sweep happens.
	for i := 0; i < sweepEvery+1; i++ {
		rl.allow("active-user", 1000)
	}

	rl.mu.Lock()
	_, stillPresent := rl.windows["idle-user"]
	rl.mu.Unlock()
	if stillPresent {
		t.Error("idle-user's window should have been evicted by the sweep, but is still present")
	}
}
