package plugin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func callBrainDiagnostics(t *testing.T, app *App) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": "brain_diagnostics", "arguments": json.RawMessage("{}")})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, err := app.handleToolsCall(context.Background(), params, Settings{})
	if err != nil {
		t.Fatalf("handleToolsCall failed: %v", err)
	}
	var diag map[string]any
	if err := json.Unmarshal([]byte(result), &diag); err != nil {
		t.Fatalf("brain_diagnostics didn't return valid JSON: %v (%s)", err, result)
	}
	return diag
}

func TestBrainDiagnostics_NoLongerHardcoded(t *testing.T) {
	app := newTestDB(t)
	result, err := func() (string, error) {
		params, _ := json.Marshal(map[string]any{"name": "brain_diagnostics", "arguments": json.RawMessage("{}")})
		return app.handleToolsCall(context.Background(), params, Settings{})
	}()
	if err != nil {
		t.Fatalf("handleToolsCall failed: %v", err)
	}
	// The old implementation always returned these exact strings regardless
	// of real state -- confirm they're gone.
	for _, fake := range []string{`"status": "GREEN"`, "< 5ms avg", "No anomalies detected", "operating exceptionally well"} {
		if strings.Contains(result, fake) {
			t.Errorf("result still contains hardcoded claim %q:\n%s", fake, result)
		}
	}
}

func TestBrainDiagnostics_ReportsRealFactCounts(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()
	if err := app.StoreMemory(ctx, "diag-project", "fact one"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "diag-project", "fact two"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	diag := callBrainDiagnostics(t, app)
	database, ok := diag["database"].(map[string]any)
	if !ok {
		t.Fatalf("diag[\"database\"] = %#v, want a map", diag["database"])
	}
	if total, _ := database["total_facts"].(float64); total != 2 {
		t.Errorf("total_facts = %v, want 2", database["total_facts"])
	}
	if status, _ := database["status"].(string); status != "ok" {
		t.Errorf("status = %v, want \"ok\"", database["status"])
	}
}

func TestBrainDiagnostics_ReportsRealDuplicateCount(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()
	if err := app.StoreMemory(ctx, "dup-project", "the same fact twice"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "dup-project", "the same fact twice"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "dup-project", "a unique fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	diag := callBrainDiagnostics(t, app)
	database := diag["database"].(map[string]any)
	if dup, _ := database["duplicate_facts"].(float64); dup != 1 {
		t.Errorf("duplicate_facts = %v, want 1 (one exact duplicate pair)", database["duplicate_facts"])
	}
}

func TestBrainDiagnostics_AutoLearnDisabledByDefault(t *testing.T) {
	app := newTestDB(t)
	// This plugin's poller state used to be a shared package-level global
	// (see alerts.go) that could leak "started" across tests depending on
	// run order -- now it's per-App, but this App instance's own state is
	// still reset defensively.
	app.resetAutoLearnStatus()
	t.Cleanup(app.resetAutoLearnStatus)
	diag := callBrainDiagnostics(t, app)
	autoLearn, ok := diag["auto_learn_alerts"].(map[string]any)
	if !ok {
		t.Fatalf("diag[\"auto_learn_alerts\"] = %#v, want a map", diag["auto_learn_alerts"])
	}
	if enabled, _ := autoLearn["enabled"].(bool); enabled {
		t.Error("enabled = true, want false (poller never started in this test process)")
	}
}

func TestStoreMemory_AtRestEncryptionDisabledByDefault(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "plaintext-project", "a fact stored with the default settings"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	var fact string
	var isEncrypted bool
	if err := app.db.QueryRow("SELECT fact, is_encrypted FROM memory_store WHERE project = 'plaintext-project'").Scan(&fact, &isEncrypted); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if isEncrypted {
		t.Error("is_encrypted = true, want false (at-rest encryption is opt-in and off by default)")
	}
	if fact != "a fact stored with the default settings" {
		t.Errorf("fact = %q, want the raw plaintext stored directly (no encryption applied)", fact)
	}
}

func TestStoreMemory_AtRestEncryptionWhenEnabled(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()
	app.atRestEncryptionEnabled = true

	if err := app.StoreMemory(ctx, "encrypted-project", "a fact stored with encryption on"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	var fact string
	var isEncrypted bool
	if err := app.db.QueryRow("SELECT fact, is_encrypted FROM memory_store WHERE project = 'encrypted-project'").Scan(&fact, &isEncrypted); err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if !isEncrypted {
		t.Error("is_encrypted = false, want true (at-rest encryption was explicitly enabled)")
	}
	if fact == "a fact stored with encryption on" {
		t.Error("fact was stored as plaintext even though at-rest encryption is enabled")
	}

	// Real functionality must still work end to end with encryption on.
	results, err := app.SearchMemory(ctx, "encrypted-project", "encryption", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 || results[0] != "a fact stored with encryption on" {
		t.Errorf("results = %v, want the fact decrypted back to its original plaintext", results)
	}
}

func TestUpsertMemory_SkipsCanonicallyIdenticalFact(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	inserted, err := app.UpsertMemory(ctx, "upsert-project", "The Vault pod restarted")
	if err != nil {
		t.Fatalf("UpsertMemory failed: %v", err)
	}
	if !inserted {
		t.Fatal("first call: inserted = false, want true (nothing stored yet)")
	}

	// Different case/whitespace, same words -- must be treated as the same fact.
	inserted, err = app.UpsertMemory(ctx, "upsert-project", "  the vault   pod restarted  ")
	if err != nil {
		t.Fatalf("UpsertMemory failed: %v", err)
	}
	if inserted {
		t.Error("second call: inserted = true, want false (canonically identical to the first)")
	}

	count, err := app.CountDuplicateFacts(ctx)
	if err != nil {
		t.Fatalf("CountDuplicateFacts failed: %v", err)
	}
	if count != 0 {
		t.Errorf("CountDuplicateFacts = %d, want 0 (upsert must not have created a duplicate row)", count)
	}
}

func TestUpsertMemory_DifferentFactsBothInserted(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	inserted1, err := app.UpsertMemory(ctx, "upsert-project-2", "fact A")
	if err != nil {
		t.Fatalf("UpsertMemory failed: %v", err)
	}
	inserted2, err := app.UpsertMemory(ctx, "upsert-project-2", "fact B")
	if err != nil {
		t.Fatalf("UpsertMemory failed: %v", err)
	}
	if !inserted1 || !inserted2 {
		t.Errorf("inserted1=%v inserted2=%v, want both true (genuinely different facts)", inserted1, inserted2)
	}
}

func TestCountDuplicateFacts_EncryptedFactsWithRandomNonceStillDetected(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()
	// At-rest encryption is opt-in and off by default (see app.go's
	// AtRestEncryptionEnabled) -- this test is specifically about the
	// encrypted case, so turn it on for its duration.
	app.atRestEncryptionEnabled = true
	// Confirms the fix actually matters: naive SQL-level dedup on the raw
	// (encrypted) column would find zero duplicates here, since AES-GCM's
	// random nonce makes two encryptions of the same plaintext produce
	// different ciphertext -- only decrypt-then-compare catches this.
	if err := app.StoreMemory(ctx, "crypto-dup-project", "identical plaintext"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "crypto-dup-project", "identical plaintext"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	var rawFacts []string
	rows, err := app.db.Query("SELECT fact FROM memory_store WHERE project = 'crypto-dup-project'")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		rawFacts = append(rawFacts, f)
	}
	if len(rawFacts) == 2 && rawFacts[0] == rawFacts[1] {
		t.Fatal("test assumption broken: ciphertexts are identical -- encryption may no longer use a random nonce")
	}

	count, err := app.CountDuplicateFacts(ctx)
	if err != nil {
		t.Fatalf("CountDuplicateFacts failed: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
}
