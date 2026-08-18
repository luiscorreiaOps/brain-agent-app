package plugin

import (
	"context"
	"testing"
	"time"
)

func TestStoreMemoryWithMetadata_RoundTripsThroughListFactsWithMetadata(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemoryWithMetadata(ctx, "meta-project", "checkout latency spikes under load", &MemoryMetadata{
		Type: "incident", Tags: "perf,checkout", Service: "checkout", Namespace: "prod", Confidence: 0.8,
	}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}

	records, err := app.ListFactsWithMetadata(ctx, "meta-project")
	if err != nil {
		t.Fatalf("ListFactsWithMetadata failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	r := records[0]
	if r.Type != "incident" || r.Tags != "perf,checkout" || r.Service != "checkout" || r.Namespace != "prod" {
		t.Errorf("metadata not preserved: %+v", r)
	}
	if r.Confidence != 0.8 {
		t.Errorf("Confidence = %v, want 0.8", r.Confidence)
	}
	if r.Status != "approved" {
		t.Errorf("Status = %q, want \"approved\" (explicit store_memory-style calls are never queued)", r.Status)
	}
}

func TestStoreMemory_PlainCallStillHasNoMetadataAndIsApproved(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "plain-project", "a fact with no metadata"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	records, err := app.ListFactsWithMetadata(ctx, "plain-project")
	if err != nil {
		t.Fatalf("ListFactsWithMetadata failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	if records[0].Type != "" || records[0].Service != "" || records[0].Status != "approved" {
		t.Errorf("expected empty metadata + approved status for a plain StoreMemory call, got %+v", records[0])
	}
}

func TestSearchMemory_ExcludesExpiredFacts(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour)
	if err := app.StoreMemoryWithMetadata(ctx, "expiry-project", "an expired fact about redis", &MemoryMetadata{ExpiresAt: &past}); err != nil {
		t.Fatalf("StoreMemoryWithMetadata failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "expiry-project", "a fact that never expires about redis"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "expiry-project", "redis", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 || results[0] != "a fact that never expires about redis" {
		t.Errorf("results = %v, want only the non-expired fact", results)
	}
}

func TestSuggestMemory_IsPendingAndInvisibleToSearch(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.SuggestMemory(ctx, "suggest-project", "the model noticed a pattern"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "suggest-project", "pattern", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want empty -- a pending suggestion must not surface in normal search", results)
	}

	pending, err := app.ListPendingFacts(ctx, "suggest-project")
	if err != nil {
		t.Fatalf("ListPendingFacts failed: %v", err)
	}
	if len(pending) != 1 || pending[0].Status != "pending" || pending[0].Source != "llm-suggested" {
		t.Fatalf("pending = %+v, want one pending/llm-suggested record", pending)
	}
}

func TestApprovePendingFact_MakesItSearchable(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.SuggestMemory(ctx, "approve-project", "a fact about kafka lag"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}
	pending, err := app.ListPendingFacts(ctx, "approve-project")
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFacts failed: %v (%v)", err, pending)
	}

	if err := app.ApprovePendingFact(ctx, pending[0].ID); err != nil {
		t.Fatalf("ApprovePendingFact failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "approve-project", "kafka", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 || results[0] != "a fact about kafka lag" {
		t.Errorf("results = %v, want the approved fact to now be searchable", results)
	}

	stillPending, err := app.ListPendingFacts(ctx, "approve-project")
	if err != nil {
		t.Fatalf("ListPendingFacts failed: %v", err)
	}
	if len(stillPending) != 0 {
		t.Errorf("stillPending = %v, want empty after approval", stillPending)
	}
}

func TestRejectPendingFact_RemovesItPermanently(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.SuggestMemory(ctx, "reject-project", "a wrong guess about the outage cause"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}
	pending, err := app.ListPendingFacts(ctx, "reject-project")
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFacts failed: %v (%v)", err, pending)
	}

	if err := app.RejectPendingFact(ctx, pending[0].ID); err != nil {
		t.Fatalf("RejectPendingFact failed: %v", err)
	}

	stillPending, err := app.ListPendingFacts(ctx, "reject-project")
	if err != nil {
		t.Fatalf("ListPendingFacts failed: %v", err)
	}
	if len(stillPending) != 0 {
		t.Errorf("stillPending = %v, want empty after rejection", stillPending)
	}

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_store WHERE id = ?", pending[0].ID).Scan(&count); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if count != 0 {
		t.Error("rejected suggestion row still exists in memory_store, want fully deleted")
	}
}

func TestApproveRejectPendingFact_UnknownIDReturnsError(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.ApprovePendingFact(ctx, 999999); err == nil {
		t.Error("expected an error approving a non-existent id, got nil")
	}
	if err := app.RejectPendingFact(ctx, 999999); err == nil {
		t.Error("expected an error rejecting a non-existent id, got nil")
	}
}

func TestGetProjectStats_ExcludesPendingSuggestions(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "stats-project", "an approved fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.SuggestMemory(ctx, "stats-project", "a pending suggestion"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}

	stats, err := app.GetProjectStats(ctx)
	if err != nil {
		t.Fatalf("GetProjectStats failed: %v", err)
	}
	if stats["stats-project"] != 1 {
		t.Errorf("stats[\"stats-project\"] = %d, want 1 (pending suggestion must not count)", stats["stats-project"])
	}
}

// A project can have a pending suggestion before it ever has a single
// approved fact -- GetProjectStats (Active Contexts & Projects) would never
// mention it, so the Brain Hub UI needs ProjectsWithPendingFacts to find it.
func TestProjectsWithPendingFacts_FindsProjectWithNoApprovedFactsYet(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.SuggestMemory(ctx, "brand-new-project", "an inferred observation"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}

	stats, err := app.GetProjectStats(ctx)
	if err != nil {
		t.Fatalf("GetProjectStats failed: %v", err)
	}
	if _, ok := stats["brand-new-project"]; ok {
		t.Fatalf("stats unexpectedly contains brand-new-project -- test setup is wrong")
	}

	projects, err := app.ProjectsWithPendingFacts(ctx)
	if err != nil {
		t.Fatalf("ProjectsWithPendingFacts failed: %v", err)
	}
	found := false
	for _, p := range projects {
		if p == "brand-new-project" {
			found = true
		}
	}
	if !found {
		t.Errorf("ProjectsWithPendingFacts = %v, want it to include brand-new-project", projects)
	}
}
