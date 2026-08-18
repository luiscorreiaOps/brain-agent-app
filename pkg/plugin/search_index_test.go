package plugin

import (
	"context"
	"strings"
	"testing"
)

func TestTokenize_StripsAccentsLowercasesAndDropsStopwords(t *testing.T) {
	got := tokenize("O Vault NÃO consegue conectar ao Código de índice")
	want := []string{"vault", "nao", "consegue", "conectar", "ao", "codigo", "indice"}
	// "o", "de" are stopwords and must be gone; "ao" is not in our
	// deliberately small stopword list and should survive.
	if len(got) != len(want) {
		t.Fatalf("tokenize() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tokenize()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestTokenize_DropsShortTokensAndStopwords(t *testing.T) {
	got := tokenize("a e o de para")
	if len(got) != 0 {
		t.Errorf("tokenize(all stopwords) = %v, want empty", got)
	}
}

func TestHMACToken_SameInputSameOutput_DifferentInputDifferentOutput(t *testing.T) {
	app := newTestDB(t) // initializes hmacKey via InitDB -> InitSearchIndexKey

	h1, err := app.hmacToken("sre-team", "vault")
	if err != nil {
		t.Fatalf("hmacToken failed: %v", err)
	}
	h2, err := app.hmacToken("sre-team", "vault")
	if err != nil {
		t.Fatalf("hmacToken failed: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hmacToken(\"vault\") is non-deterministic: %q != %q", h1, h2)
	}

	h3, err := app.hmacToken("sre-team", "kafka")
	if err != nil {
		t.Fatalf("hmacToken failed: %v", err)
	}
	if h1 == h3 {
		t.Error("hmacToken(\"vault\") == hmacToken(\"kafka\"), want different hashes for different tokens")
	}

	if strings.Contains(h1, "vault") {
		t.Errorf("hmacToken output contains the plaintext token: %q", h1)
	}
}

// Security-audit finding M4: the same word in two different projects used
// to produce the identical HMAC value, letting someone with raw .db file
// access (no hmac key needed) correlate vocabulary across projects that
// are otherwise meant to be isolated. project is now folded into the HMAC
// input, so the same token in different projects must hash differently.
func TestHMACToken_SameTokenDifferentProjectsDifferentHash(t *testing.T) {
	app := newTestDB(t)

	h1, err := app.hmacToken("finance-team", "acquisition")
	if err != nil {
		t.Fatalf("hmacToken failed: %v", err)
	}
	h2, err := app.hmacToken("hr-team", "acquisition")
	if err != nil {
		t.Fatalf("hmacToken failed: %v", err)
	}
	if h1 == h2 {
		t.Error("hmacToken(\"acquisition\") produced the same hash for two different projects, want project-scoped hashes")
	}
}

func TestSearchMemory_IndexFindsFactByAccentInsensitiveTerm(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "index-project", "O serviço não consegue conectar ao Vault"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	// Query without the accent that the stored fact has ("nao" vs "não") --
	// must still match via the index's accent-stripped tokens.
	results, err := app.SearchMemory(ctx, "index-project", "nao consegue", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly 1 match via the accent-insensitive index", results)
	}
}

func TestSearchMemory_IndexPathMatchesFullScanRanking(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	// scoreFact counts each distinct term match once (plus one exact-phrase
	// bonus) -- it does NOT reward repeated occurrences of the same term,
	// so these two facts must differ in DISTINCT matched terms, not just
	// word count, for the ranking to be unambiguous.
	if err := app.StoreMemory(ctx, "rank-project", "vault restart resolved the incident"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "rank-project", "vault was mentioned in passing"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "rank-project", "vault restart", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %v, want 2 matches", results)
	}
	if !strings.Contains(results[0], "vault restart resolved") {
		t.Errorf("results[0] = %q, want the fact matching BOTH query terms (plus phrase bonus) ranked first", results[0])
	}
}

func TestSearchMemory_StopwordOnlyQueryFallsBackToFullScan(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "fallback-project", "a fact with real content"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	// "de para" is entirely stopwords -- tokenize() yields nothing, so the
	// index path must report itself unusable rather than "zero matches",
	// letting the full-scan fallback run (which, per its own long-standing
	// behavior, returns recent facts when nothing scores).
	results, err := app.SearchMemory(ctx, "fallback-project", "de para", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("results = %v, want the fallback's 1 recent fact, not an empty result", results)
	}
}

func TestDeleteMemory_RemovesIndexRows(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "delete-index-project", "unique searchable fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.DeleteMemory(ctx, "delete-index-project", "unique searchable fact"); err != nil {
		t.Fatalf("DeleteMemory failed: %v", err)
	}

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_index WHERE project = ?", "delete-index-project").Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 0 {
		t.Errorf("memory_index rows for deleted fact = %d, want 0 (orphaned index entries)", count)
	}
}

func TestClearProjectMemories_RemovesIndexRows(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "clear-index-project", "a fact to be cleared"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.ClearProjectMemories(ctx, "clear-index-project"); err != nil {
		t.Fatalf("ClearProjectMemories failed: %v", err)
	}

	var count int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_index WHERE project = ?", "clear-index-project").Scan(&count); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 0 {
		t.Errorf("memory_index rows after ClearProjectMemories = %d, want 0", count)
	}
}

func TestBackfillSearchIndexIfNeeded_IndexesPreExistingFacts(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	// Simulate a fact written before the index existed: insert directly,
	// bypassing StoreMemory's own indexFact call.
	encrypted, err := app.Encrypt("a pre-existing fact about redis")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if _, err := app.db.Exec("INSERT INTO memory_store (project, fact, is_encrypted) VALUES (?, ?, 1)", "backfill-project", encrypted); err != nil {
		t.Fatalf("direct insert failed: %v", err)
	}

	var countBefore int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM memory_index WHERE project = ?", "backfill-project").Scan(&countBefore); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if countBefore != 0 {
		t.Fatalf("countBefore = %d, want 0 (test setup should have bypassed indexing)", countBefore)
	}

	app.backfillSearchIndexIfNeeded(ctx)

	results, err := app.SearchMemory(ctx, "backfill-project", "redis", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("results = %v, want the backfilled fact to be found via the index", results)
	}
}

func TestCondenseMemory_CleansUpAndReindexes(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "condense-project", "old fact one about vault"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "condense-project", "old fact two about vault"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	err := app.CondenseMemory(ctx, "condense-project", "golden record about kafka", []string{
		"old fact one about vault", "old fact two about vault",
	})
	if err != nil {
		t.Fatalf("CondenseMemory failed: %v", err)
	}

	// Old facts' index rows must be gone -- searching their old term finds nothing.
	oldResults, err := app.SearchMemory(ctx, "condense-project", "vault", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	for _, r := range oldResults {
		if strings.Contains(r, "old fact") {
			t.Errorf("found stale old fact after condense: %q", r)
		}
	}

	// New golden record must be indexed and searchable.
	newResults, err := app.SearchMemory(ctx, "condense-project", "kafka", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(newResults) != 1 || !strings.Contains(newResults[0], "golden record") {
		t.Errorf("newResults = %v, want the new golden record findable via its own index entry", newResults)
	}
}
