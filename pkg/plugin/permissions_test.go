package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

// withRole returns a request whose context carries the given Grafana org
// role, the same way the real plugin SDK attaches it to every inbound
// request -- see backend.WithPluginContext's own doc comment ("unless in
// tests and such").
func withRole(t *testing.T, method, target, role string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	ctx := req.Context()
	if role != "" {
		ctx = backend.WithPluginContext(ctx, backend.PluginContext{User: &backend.User{Role: role}})
	}
	return req.WithContext(ctx)
}

// Security-audit finding M2: crypto reset is disaster recovery, not
// routine content management -- Admin-only, not Editor+Admin like most of
// this file's other write actions.
func TestRequireAdmin_BlocksEditorAllowsAdmin(t *testing.T) {
	w := httptest.NewRecorder()
	if requireAdmin(w, withRole(t, http.MethodPost, "/x", "Editor")) {
		t.Error("requireAdmin should reject Editor")
	}
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for Editor", w.Result().StatusCode)
	}

	w2 := httptest.NewRecorder()
	if !requireAdmin(w2, withRole(t, http.MethodPost, "/x", "Admin")) {
		t.Error("requireAdmin should allow Admin")
	}
}

func TestRequireEditorOrAdmin_AllowsEditorAndAdmin(t *testing.T) {
	for _, role := range []string{"Editor", "Admin"} {
		t.Run(role, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := withRole(t, http.MethodPost, "/x", role)
			if !requireEditorOrAdmin(w, req) {
				t.Errorf("requireEditorOrAdmin(role=%s) = false, want true", role)
			}
			if w.Code != http.StatusOK && w.Code != 200 {
				// requireEditorOrAdmin itself never writes a success status --
				// just confirm it didn't write an error status either.
				if w.Result().StatusCode >= 400 {
					t.Errorf("unexpected error status %d written for role=%s", w.Result().StatusCode, role)
				}
			}
		})
	}
}

func TestRequireEditorOrAdmin_BlocksViewerAndMissingRole(t *testing.T) {
	for _, role := range []string{"Viewer", ""} {
		t.Run("role="+role, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := withRole(t, http.MethodPost, "/x", role)
			if requireEditorOrAdmin(w, req) {
				t.Errorf("requireEditorOrAdmin(role=%q) = true, want false", role)
			}
			if w.Result().StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", w.Result().StatusCode)
			}
		})
	}
}

func TestHandleMemoryClear_ViewerForbidden(t *testing.T) {
	app := newTestDB(t)
	app.registerRoutes()

	req := withRole(t, http.MethodDelete, "/memory?project_id=all", "Viewer")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a Viewer", w.Result().StatusCode)
	}
}

func TestHandleMemoryClear_EditorAllowed(t *testing.T) {
	app := newTestDB(t)
	ctx := withRole(t, http.MethodDelete, "/memory?project_id=all", "Editor").Context()
	if err := app.StoreMemory(ctx, "perm-test-project", "a fact to be cleared"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	app.registerRoutes()

	req := withRole(t, http.MethodDelete, "/memory?project_id=all", "Editor")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for an Editor", w.Result().StatusCode)
	}
}

// Reviewing an LLM's own suggestions (approve/reject) is the one write
// action Viewers are explicitly allowed to perform in Brain Hub -- every
// other write endpoint (memory clear, encryption toggles, key reset) stays
// gated to Editor/Admin, covered separately below.
// Security-audit follow-up: approve used to be open to Viewer on the same
// "reviewing an LLM's own suggestion" reasoning reject still has -- but
// approve isn't a review, it's the review's OUTCOME. Combined with
// suggest_memory already being open to Viewer, and id being a bare
// sequential integer with no project/org scope check, a Viewer could
// suggest a fact and immediately approve that exact id themselves,
// promoting it to real, searchable memory with zero actual human review.
// This is the live self-approval scenario, not a hypothetical.
func TestHandleApprovePendingFact_ViewerCannotSelfApproveOwnSuggestion(t *testing.T) {
	app := newTestDB(t)
	viewerCtx := withRole(t, http.MethodPost, "/", "Viewer").Context()
	if err := app.SuggestMemory(viewerCtx, "perm-test-project", "a viewer's own suggestion"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}
	pending, err := app.ListPendingFacts(viewerCtx, "perm-test-project")
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFacts failed: %v (%v)", err, pending)
	}

	app.registerRoutes()

	approveReq := withRole(t, http.MethodPost, fmt.Sprintf("/pending_facts/approve?id=%d", pending[0].ID), "Viewer")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, approveReq)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("approve: status = %d, want 403 -- a Viewer must never be able to approve their own (or anyone else's) suggestion", w.Result().StatusCode)
	}

	stillPending, err := app.ListPendingFacts(viewerCtx, "perm-test-project")
	if err != nil {
		t.Fatalf("ListPendingFacts failed: %v", err)
	}
	if len(stillPending) != 1 {
		t.Errorf("stillPending = %v, want the suggestion to remain pending after a forbidden approve attempt", stillPending)
	}
}

func TestHandleApprovePendingFact_EditorAllowed(t *testing.T) {
	app := newTestDB(t)
	ctx := withRole(t, http.MethodPost, "/", "Editor").Context()
	if err := app.SuggestMemory(ctx, "perm-test-project", "fact to approve"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}
	pending, err := app.ListPendingFacts(ctx, "perm-test-project")
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFacts failed: %v (%v)", err, pending)
	}

	app.registerRoutes()

	approveReq := withRole(t, http.MethodPost, fmt.Sprintf("/pending_facts/approve?id=%d", pending[0].ID), "Editor")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, approveReq)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("approve: status = %d, want 200 for an Editor", w.Result().StatusCode)
	}
}

// Rejecting stays open to Viewer -- discarding an unreviewed suggestion
// (never promoting it) is strictly lower risk than approving one.
func TestHandleRejectPendingFact_ViewerAllowed(t *testing.T) {
	app := newTestDB(t)
	ctx := withRole(t, http.MethodPost, "/", "Viewer").Context()
	if err := app.SuggestMemory(ctx, "perm-test-project", "fact to reject"); err != nil {
		t.Fatalf("SuggestMemory failed: %v", err)
	}
	pending, err := app.ListPendingFacts(ctx, "perm-test-project")
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingFacts failed: %v (%v)", err, pending)
	}

	app.registerRoutes()

	rejectReq := withRole(t, http.MethodPost, fmt.Sprintf("/pending_facts/reject?id=%d", pending[0].ID), "Viewer")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, rejectReq)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("reject: status = %d, want 200 for a Viewer", w.Result().StatusCode)
	}

	stillPending, err := app.ListPendingFacts(ctx, "perm-test-project")
	if err != nil {
		t.Fatalf("ListPendingFacts failed: %v", err)
	}
	if len(stillPending) != 0 {
		t.Errorf("stillPending = %v, want the rejected suggestion gone", stillPending)
	}
}

// Reading approved fact content is gated too -- a Viewer can see project
// names/counts and the Pending Suggestions queue, but not the actual stored
// memory text behind "View".
func TestHandleFacts_ViewerForbidden(t *testing.T) {
	app := newTestDB(t)
	adminCtx := withRole(t, http.MethodPost, "/", "Admin").Context()
	if err := app.StoreMemory(adminCtx, "perm-test-project", "an approved fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	app.registerRoutes()

	req := withRole(t, http.MethodGet, "/facts?project=perm-test-project", "Viewer")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a Viewer", w.Result().StatusCode)
	}
}

// callMCP drives handleMCPDirect directly (the JSON-RPC path bypasses
// app.mux entirely, see CallResource in app.go), capturing whatever it
// sends back so the test can assert on status/body.
func callMCP(t *testing.T, app *App, role string, toolName string, args map[string]any) *backend.CallResourceResponse {
	t.Helper()
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	params, err := json.Marshal(map[string]any{"name": toolName, "arguments": json.RawMessage(argsJSON)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	ctx := withRole(t, http.MethodPost, "/mcp", role).Context()
	// Fresh logger/limiter per call, same as this helper's original
	// from-scratch App{} -- only the db (and everything else already on
	// app) is shared/reused across calls now.
	app.logger = log.NewNullLogger()
	app.limiter = newPerUserRateLimiter()
	req := &backend.CallResourceRequest{Path: "mcp", Method: http.MethodPost, Body: body}

	var got *backend.CallResourceResponse
	sender := backend.CallResourceResponseSenderFunc(func(resp *backend.CallResourceResponse) error {
		got = resp
		return nil
	})
	if err := app.handleMCPDirect(ctx, req, sender); err != nil {
		t.Fatalf("handleMCPDirect error: %v", err)
	}
	if got == nil {
		t.Fatalf("handleMCPDirect never sent a response")
	}
	return got
}

// callMCPAs is callMCP plus an explicit Login on the request's plugin
// context -- needed for the TrustedIntegrationLogin tests below, since
// callMCP's underlying withRole only ever sets Role.
func callMCPAs(t *testing.T, app *App, role, login, toolName string, args map[string]any) *backend.CallResourceResponse {
	t.Helper()
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	params, err := json.Marshal(map[string]any{"name": toolName, "arguments": json.RawMessage(argsJSON)})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ctx := backend.WithPluginContext(req.Context(), backend.PluginContext{User: &backend.User{Role: role, Login: login}})
	app.logger = log.NewNullLogger()
	app.limiter = newPerUserRateLimiter()
	resourceReq := &backend.CallResourceRequest{Path: "mcp", Method: http.MethodPost, Body: body}

	var got *backend.CallResourceResponse
	sender := backend.CallResourceResponseSenderFunc(func(resp *backend.CallResourceResponse) error {
		got = resp
		return nil
	})
	if err := app.handleMCPDirect(ctx, resourceReq, sender); err != nil {
		t.Fatalf("handleMCPDirect error: %v", err)
	}
	if got == nil {
		t.Fatalf("handleMCPDirect never sent a response")
	}
	return got
}

// Security-audit finding: tools/call is a separate dispatch path from the
// HTTP resource routes above and wasn't covered by requireEditorOrAdmin at
// all -- live-confirmed a Viewer-role token could store_memory/delete_memory
// through it. store_memory/upsert_memory/delete_memory/condense_memory must
// now 403 for Viewer, matching the equivalent HTTP routes.
func TestHandleMCPToolsCall_ViewerForbiddenForMutatingTools(t *testing.T) {
	app := newTestDB(t)
	for _, tool := range []string{"store_memory", "upsert_memory", "delete_memory", "condense_memory"} {
		t.Run(tool, func(t *testing.T) {
			resp := callMCP(t, app, "Viewer", tool, map[string]any{"fact": "x", "project": "perm-test-project", "condensed_fact": "x", "facts_to_delete": []string{}})
			if resp.Status != http.StatusForbidden {
				t.Errorf("tool=%s status = %d, want 403 for a Viewer", tool, resp.Status)
			}
		})
	}

	facts, err := app.SearchMemory(withRole(t, http.MethodGet, "/", "Admin").Context(), "perm-test-project", "x", false)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(facts) != 0 {
		t.Errorf("a forbidden store_memory call should not have written anything, found: %v", facts)
	}
}

func TestHandleMCPToolsCall_EditorAllowedForMutatingTools(t *testing.T) {
	app := newTestDB(t)
	resp := callMCP(t, app, "Editor", "store_memory", map[string]any{"fact": "an editor-stored fact", "project": "perm-test-project"})
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 for an Editor, body: %s", resp.Status, resp.Body)
	}
}

// Security-audit findings C2/C3/C4: search_memory, search_memory_by_time,
// and brain_diagnostics were never gated at all -- only the write/delete
// tools were. A Viewer could read every project's fully decrypted memory
// through these, and brain_diagnostics forced a full-table decrypt on
// demand. All 3 must now 403 for Viewer, same as the write tools.
func TestHandleMCPToolsCall_ViewerForbiddenForPreviouslyUngatedReads(t *testing.T) {
	app := newTestDB(t)
	adminCtx := withRole(t, http.MethodPost, "/", "Admin").Context()
	if err := app.StoreMemory(adminCtx, "perm-test-project", "a fact only Editor/Admin should be able to read via MCP search"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	cases := []struct {
		tool string
		args map[string]any
	}{
		{"search_memory", map[string]any{"project": "perm-test-project", "query": "fact"}},
		{"search_memory_by_time", map[string]any{"project": "perm-test-project", "query": "", "start_time": "2020-01-01", "end_time": "2030-01-01"}},
		{"brain_diagnostics", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			resp := callMCP(t, app, "Viewer", tc.tool, tc.args)
			if resp.Status != http.StatusForbidden {
				t.Errorf("tool=%s status = %d, want 403 for a Viewer, body: %s", tc.tool, resp.Status, resp.Body)
			}
			if strings.Contains(string(resp.Body), "perm-test-project") {
				t.Errorf("tool=%s forbidden response leaked memory content: %s", tc.tool, resp.Body)
			}
		})
	}
}

func TestHandleMCPToolsCall_EditorAllowedForPreviouslyUngatedReads(t *testing.T) {
	app := newTestDB(t)
	adminCtx := withRole(t, http.MethodPost, "/", "Admin").Context()
	if err := app.StoreMemory(adminCtx, "perm-test-project", "a fact an Editor should still be able to find"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	resp := callMCP(t, app, "Editor", "search_memory", map[string]any{"project": "perm-test-project", "query": "fact"})
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 for an Editor, body: %s", resp.Status, resp.Body)
	}
}

// suggest_memory is the one MCP tool that stays open to Viewers -- it only
// queues a suggestion for admin review, it never writes real memory itself
// (same exception already granted to approve/reject above).
func TestHandleMCPToolsCall_ViewerAllowedForSuggestMemory(t *testing.T) {
	app := newTestDB(t)
	resp := callMCP(t, app, "Viewer", "suggest_memory", map[string]any{"fact": "a viewer-suggested fact", "project": "perm-test-project"})
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 for a Viewer calling suggest_memory, body: %s", resp.Status, resp.Body)
	}
}

// ============================================================================
// TrustedIntegrationLogin -- narrow exception for agent-ai-app's own Viewer
// service account (see mcpCallAllowed's doc comment in resources.go).
// Tested extensively: this grants access, so every boundary needs its own
// test proving the grant is exactly as narrow as intended, not broader.
// ============================================================================

const trustedLoginForTests = "sa-llm-plugin"

// The 3 read-only tools the exception covers -- kept as one shared list so
// every sub-test below iterates the identical set the production code
// checks (trustedIntegrationReadOnlyTools).
var trustedIntegrationTestTools = []struct {
	tool string
	args map[string]any
}{
	{"search_memory", map[string]any{"project": "trusted-login-project", "query": "fact"}},
	{"search_memory_by_time", map[string]any{"project": "trusted-login-project", "query": "fact", "start_time": "2020-01-01", "end_time": "2030-01-01"}},
	{"brain_diagnostics", map[string]any{}},
}

func TestMCPCallAllowed_TrustedLoginAllowsReadOnlyToolsAtViewerRole(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests
	adminCtx := withRole(t, http.MethodPost, "/", "Admin").Context()
	if err := app.StoreMemory(adminCtx, "trusted-login-project", "a fact the trusted integration should be able to read"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	for _, tc := range trustedIntegrationTestTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp := callMCPAs(t, app, "Viewer", trustedLoginForTests, tc.tool, tc.args)
			if resp.Status != http.StatusOK {
				t.Errorf("tool=%s status = %d, want 200 for the trusted login at Viewer role, body: %s", tc.tool, resp.Status, resp.Body)
			}
		})
	}
}

// The exception must never extend to write/delete tools -- a Viewer-role
// identity, trusted or not, still needs real Editor/Admin for those. If
// this ever passed, agent-ai-app's Viewer SA could write/delete memory
// through brain-agent, which was never the intent (H-07's whole point was
// the opposite).
func TestMCPCallAllowed_TrustedLoginStillBlockedForWriteTools(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests

	for _, tool := range []string{"store_memory", "upsert_memory", "delete_memory", "condense_memory"} {
		t.Run(tool, func(t *testing.T) {
			resp := callMCPAs(t, app, "Viewer", trustedLoginForTests, tool, map[string]any{
				"fact": "x", "project": "trusted-login-project", "condensed_fact": "x", "facts_to_delete": []string{},
			})
			if resp.Status != http.StatusForbidden {
				t.Errorf("tool=%s status = %d, want 403 -- the trusted-login exception must never cover write/delete tools", tool, resp.Status)
			}
		})
	}
}

// A Viewer whose login does NOT match Settings.TrustedIntegrationLogin must
// be denied exactly like before this feature existed -- proving this is a
// grant to one specific identity, not "any Viewer with some login set".
func TestMCPCallAllowed_NonMatchingLoginStaysBlocked(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests

	for _, tc := range trustedIntegrationTestTools {
		t.Run(tc.tool, func(t *testing.T) {
			resp := callMCPAs(t, app, "Viewer", "some-other-viewer", tc.tool, tc.args)
			if resp.Status != http.StatusForbidden {
				t.Errorf("tool=%s status = %d, want 403 for a Viewer whose login doesn't match TrustedIntegrationLogin, body: %s", tc.tool, resp.Status, resp.Body)
			}
		})
	}
}

// A Viewer with NO login at all (backend.User.Login == "", e.g. a request
// Grafana's own backend initiated) must also stay blocked -- requestUser
// falls back to "anonymous" for that case, which must never accidentally
// equal a configured TrustedIntegrationLogin.
func TestMCPCallAllowed_EmptyLoginStaysBlockedEvenWithTrustedLoginConfigured(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests

	resp := callMCPAs(t, app, "Viewer", "", "search_memory", map[string]any{"project": "trusted-login-project", "query": "fact"})
	if resp.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a Viewer with an empty login", resp.Status)
	}
}

// The match is an exact, case-sensitive string compare (Grafana logins are
// case-sensitive) -- a differently-cased login must not match.
func TestMCPCallAllowed_LoginMatchIsCaseSensitive(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests

	resp := callMCPAs(t, app, "Viewer", strings.ToUpper(trustedLoginForTests), "search_memory", map[string]any{"project": "trusted-login-project", "query": "fact"})
	if resp.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a differently-cased login (%q vs configured %q)", resp.Status, strings.ToUpper(trustedLoginForTests), trustedLoginForTests)
	}
}

// Regression safety: with TrustedIntegrationLogin left unset (the default,
// zero value), every Viewer -- regardless of login -- must be denied
// exactly as it was before this feature existed. This is the test that
// would fail if the empty-string check in mcpCallAllowed were ever removed
// or inverted.
func TestMCPCallAllowed_EmptyTrustedIntegrationLoginPreservesOldBehavior(t *testing.T) {
	app := newTestDB(t)
	// app.settings.TrustedIntegrationLogin left as the zero value ("").

	for _, tc := range trustedIntegrationTestTools {
		t.Run(tc.tool, func(t *testing.T) {
			// Even a login of "" (which requestUser would normalize to
			// "anonymous") must not accidentally match an empty configured
			// value -- mcpCallAllowed requires TrustedIntegrationLogin != ""
			// as a precondition specifically to rule this out.
			resp := callMCPAs(t, app, "Viewer", "", tc.tool, tc.args)
			if resp.Status != http.StatusForbidden {
				t.Errorf("tool=%s status = %d, want 403 with TrustedIntegrationLogin unset", tc.tool, resp.Status)
			}
		})
	}
}

// Editor/Admin must stay fully unaffected by this feature in every
// direction: allowed with or without a matching login, whether or not
// TrustedIntegrationLogin is configured at all.
func TestMCPCallAllowed_EditorAndAdminUnaffectedByTrustedLoginSetting(t *testing.T) {
	for _, trusted := range []string{"", trustedLoginForTests} {
		for _, role := range []string{"Editor", "Admin"} {
			t.Run(role+"/trusted="+trusted, func(t *testing.T) {
				app := newTestDB(t)
				app.settings.TrustedIntegrationLogin = trusted
				resp := callMCPAs(t, app, role, "someone-else-entirely", "search_memory", map[string]any{"project": "trusted-login-project", "query": "fact"})
				if resp.Status != http.StatusOK {
					t.Errorf("status = %d, want 200 for role=%s regardless of TrustedIntegrationLogin=%q", resp.Status, role, trusted)
				}
			})
		}
	}
}

// suggest_memory must stay open to every Viewer regardless of login or
// TrustedIntegrationLogin -- that grant is independent of this feature
// (viewerSafeMCPTools, checked before the trusted-login branch even runs).
func TestMCPCallAllowed_SuggestMemoryStillOpenToAnyViewerRegardlessOfTrustedLogin(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests

	resp := callMCPAs(t, app, "Viewer", "some-unrelated-login", "suggest_memory", map[string]any{"fact": "x", "project": "trusted-login-project"})
	if resp.Status != http.StatusOK {
		t.Errorf("status = %d, want 200 -- suggest_memory stays open to any Viewer independent of TrustedIntegrationLogin", resp.Status)
	}
}

// A malformed/unparseable tools/call params blob must fail closed (deny)
// even when a trusted login is configured and used -- mcpToolName returns
// "" on unmarshal failure, which must not match a real tool name in either
// allowlist.
func TestMCPCallAllowed_MalformedToolNameFailsClosedEvenForTrustedLogin(t *testing.T) {
	app := newTestDB(t)
	app.settings.TrustedIntegrationLogin = trustedLoginForTests
	app.logger = log.NewNullLogger()
	app.limiter = newPerUserRateLimiter()

	// Deliberately malformed: "name" is a number, not a string, so
	// json.Unmarshal into the { Name string } struct fails and
	// mcpToolName returns "".
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}`)
	ctx := backend.WithPluginContext(context.Background(), backend.PluginContext{User: &backend.User{Role: "Viewer", Login: trustedLoginForTests}})
	req := &backend.CallResourceRequest{Path: "mcp", Method: http.MethodPost, Body: body}

	var got *backend.CallResourceResponse
	sender := backend.CallResourceResponseSenderFunc(func(resp *backend.CallResourceResponse) error {
		got = resp
		return nil
	})
	if err := app.handleMCPDirect(ctx, req, sender); err != nil {
		t.Fatalf("handleMCPDirect error: %v", err)
	}
	if got.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for malformed tool name, body: %s", got.Status, got.Body)
	}
}

// Security-audit finding M3: the "RPC Bus" status used to come from a
// /tmp sentinel file -- it now reflects real plugin settings.
func TestHandleStatusEncryption_ReflectsSettings(t *testing.T) {
	newTestDB(t)

	for _, enabled := range []bool{true, false} {
		app := &App{settings: Settings{InTransitEncryptionEnabled: enabled}}
		app.registerRoutes()

		req := httptest.NewRequest(http.MethodGet, "/encryption_in_transit/status", nil)
		w := httptest.NewRecorder()
		app.mux.ServeHTTP(w, req)

		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body.Enabled != enabled {
			t.Errorf("settings.InTransitEncryptionEnabled=%v -> reported enabled=%v, want %v", enabled, body.Enabled, enabled)
		}
	}
}

func TestHandleFacts_EditorAllowed(t *testing.T) {
	app := newTestDB(t)
	adminCtx := withRole(t, http.MethodPost, "/", "Admin").Context()
	if err := app.StoreMemory(adminCtx, "perm-test-project", "an approved fact"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	app.registerRoutes()

	req := withRole(t, http.MethodGet, "/facts?project=perm-test-project", "Editor")
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 for an Editor", w.Result().StatusCode)
	}
}
