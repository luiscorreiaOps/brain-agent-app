package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

// In-memory globals removed; using SQLite instead

func (a *App) registerRoutes() {
	a.mux = http.NewServeMux()
	a.mux.HandleFunc("/stats", a.handleStats)
	a.mux.HandleFunc("/facts", a.handleFacts)
	a.mux.HandleFunc("/encryption_in_transit/status", a.handleStatusEncryption)
	a.mux.HandleFunc("/crypto/reset", a.handleCryptoReset)
	a.mux.HandleFunc("/memory", a.handleMemoryClear)
	a.mux.HandleFunc("/health", a.handleHealth)
	a.mux.HandleFunc("/pending_facts", a.handlePendingFacts)
	a.mux.HandleFunc("/pending_facts/projects", a.handlePendingProjects)
	a.mux.HandleFunc("/pending_facts/approve", a.handleApprovePendingFact)
	a.mux.HandleFunc("/pending_facts/reject", a.handleRejectPendingFact)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Basic check to see if DB is reachable
	err := a.PingDB()

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		// json.NewEncoder, not fmt.Fprintf -- an error message containing a
		// quote or backslash used to produce invalid JSON (security-audit
		// finding M6).
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "message": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "ok", "message": "database connected"}`))
}

func (a *App) handleCryptoReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Admin-only, not Editor+Admin (security-audit finding M2): this is
	// disaster recovery -- resetting the encryption key and wiping the
	// database -- not routine content management like clearing memory or
	// flipping a setting.
	if !requireAdmin(w, r) {
		return
	}

	// The app initializes DB and Crypto with dataDir="/var/lib/grafana". The
	// DB filename is derived from the installed plugin directory name (see
	// detectPluginDirName/NewApp in app.go) plus this instance's own org
	// suffix (see dbNameForOrg, H8), not a fixed "brain-agent" -- a
	// forked/rebranded install has a different directory name and therefore
	// a different real DB file, and an org other than the default one has a
	// different real DB file too. This used to be hardcoded to
	// "brain-agent.db": on a fork, the os.Rename below silently failed
	// (error discarded), InitDB then just reopened the same untouched
	// db/key files, and this endpoint still reported "crypto reset
	// successful" -- a false-positive on the one button whose entire job is
	// disaster recovery.
	const dataDir = "/var/lib/grafana"
	pluginDirName := detectPluginDirName()
	dbName := orgSuffixedName(pluginDirName, a.orgID)
	keyPath, hmacKeyPath, dbPath := cryptoResetPaths(dataDir, dbName, a.orgID)

	timestamp := time.Now().Unix()

	// Close DB to release file locks before renaming
	_ = a.CloseDB()

	if err := backupFilesAtomically(dataDir, []string{keyPath, hmacKeyPath, dbPath}, timestamp); err != nil {
		a.logger.Error("crypto reset: aborted, backup was not fully applied", "error", err)
		http.Error(w, fmt.Sprintf("crypto reset aborted, nothing was changed: %v", err), http.StatusInternalServerError)
		return
	}

	// Attempt to reinitialize db and crypto. If EncryptionKey is configured
	// (L3), this re-derives the same key from settings rather than
	// generating a new one -- a settings-based key can't be silently
	// rotated by a filesystem-level reset without the admin updating that
	// setting too, and doing so without their knowledge would strand
	// already-encrypted data.
	if err := a.InitDB(dataDir, dbName, a.settings.EncryptionKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "ok", "message": "crypto reset successful"}`))
}

// backupFilesAtomically renames each of paths to "<path>.bkp_<timestamp>",
// treating the group as one unit (security-audit finding M2): if any
// rename hits a real error (not the expected "source doesn't exist" --
// e.g. at-rest encryption was never enabled, so there's no key file), it
// rolls back every rename already done in this call, so a partial failure
// never leaves the key renamed but the database not (or vice versa) --
// exactly the kind of mixed state that made the crypto-reset endpoint
// worth fixing in the first place. Once every rename in the group has
// succeeded, fsyncs the parent directory so the renames are durable
// against a crash immediately after this call returns, not just atomic
// while the process stays up.
func backupFilesAtomically(dataDir string, paths []string, timestamp int64) error {
	type done struct{ from, to string }
	var applied []done

	rollback := func() {
		for i := len(applied) - 1; i >= 0; i-- {
			if err := os.Rename(applied[i].to, applied[i].from); err != nil {
				log.DefaultLogger.Error("crypto reset: rollback rename failed, manual cleanup may be needed", "from", applied[i].to, "to", applied[i].from, "error", err)
			}
		}
	}

	for _, p := range paths {
		backupPath := fmt.Sprintf("%s.bkp_%d", p, timestamp)
		if err := os.Rename(p, backupPath); err != nil {
			if os.IsNotExist(err) {
				// Expected: e.g. at-rest encryption was never enabled, so
				// there's no key file to back up. Nothing to roll back for
				// this path, continue with the rest of the group.
				continue
			}
			rollback()
			return fmt.Errorf("back up %s: %w", p, err)
		}
		applied = append(applied, done{from: p, to: backupPath})
	}

	dir, err := os.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open data directory for fsync: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("fsync data directory: %w", err)
	}
	return nil
}

// handleStatusEncryption is the authoritative source of the "RPC Bus"
// toggle for agent-ai-app's own MCP client to check (see its
// inTransitEncodingEnabled) -- reads real plugin settings now, not a
// sentinel file both plugins used to read directly off the shared pod
// filesystem (security-audit finding M3). Toggling it is done through
// Grafana's own settings API from the frontend (BrainHub.tsx's
// savePluginSetting), same as every other toggle on this page -- there is
// no longer a separate POST /encryption_in_transit/toggle route.
func (a *App) handleStatusEncryption(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": a.settings.InTransitEncryptionEnabled})
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats, err := a.GetProjectStats(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

// handleFacts lists the actual stored facts for one project, with their
// structured metadata (type/tags/service/namespace/confidence/expiresAt) --
// until now the UI ("Active Contexts & Projects") could only ever show an
// aggregate count per project, with a "Clear Data" button and nothing to
// inspect before wiping it. Recency-ordered, not scored (there's no query
// here). Only approved, non-expired facts -- pending suggestions live in
// handlePendingFacts instead. Gated to Editor/Admin: the content of already-
// approved memories can include sensitive incident/runbook detail, so
// Viewers see project names and counts but not the facts themselves --
// unlike handlePendingFacts, which stays open to Viewers since reviewing a
// suggestion requires reading it.
func (a *App) handleFacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireEditorOrAdmin(w, r) {
		return
	}

	project := r.URL.Query().Get("project")
	if project == "" {
		project = "default"
	}

	facts, err := a.ListFactsWithMetadata(r.Context(), project)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if facts == nil {
		facts = []MemoryRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"project": project, "facts": facts})
}

// handlePendingFacts lists LLM-suggested memories (via suggest_memory) still
// awaiting admin approval, for the Brain Hub's Pending Suggestions card.
func (a *App) handlePendingFacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	project := r.URL.Query().Get("project")
	if project == "" {
		project = "default"
	}

	facts, err := a.ListPendingFacts(r.Context(), project)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if facts == nil {
		facts = []MemoryRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"project": project, "facts": facts})
}

// handlePendingProjects lists every project that has at least one pending
// suggestion, including a project with zero approved facts (so it would
// never show up in /stats). The Brain Hub UI uses this to know which
// projects to check via handlePendingFacts, instead of only checking
// projects it already knows about from the approved-facts stats.
func (a *App) handlePendingProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projects, err := a.ProjectsWithPendingFacts(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if projects == nil {
		projects = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"projects": projects})
}

// handleApprovePendingFact promotes one pending suggestion to a real,
// searchable memory. Requires Editor/Admin (security-audit follow-up):
// this used to be open to Viewers on the same "reviewing an LLM's own
// suggestion" reasoning that still applies to reject below -- but approve
// isn't a review, it's the review's OUTCOME. suggest_memory is itself open
// to Viewer (queues a suggestion, never writes real memory on its own),
// and id is a bare sequential integer with no project/org scope check --
// together, any Viewer could suggest a fact and immediately approve that
// same id (or any other project's pending id) themselves, promoting it to
// real, searchable memory with zero actual human review. Rejecting stays
// open to Viewer: discarding an unreviewed suggestion is strictly lower
// risk than promoting one.
func (a *App) handleApprovePendingFact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireEditorOrAdmin(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid or missing id", http.StatusBadRequest)
		return
	}
	if err := a.ApprovePendingFact(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// handleRejectPendingFact discards one pending suggestion permanently.
// Deliberately open to Viewers too, same reasoning as handleApprovePendingFact.
func (a *App) handleRejectPendingFact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid or missing id", http.StatusBadRequest)
		return
	}
	if err := a.RejectPendingFact(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

func (a *App) handleMemoryClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireEditorOrAdmin(w, r) {
		return
	}

	projectID := r.URL.Query().Get("project_id")
	if projectID == "all" {
		if err := a.ClearAllMemories(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if projectID != "" {
		if err := a.ClearProjectMemories(r.Context(), projectID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status": "ok", "message": "memory cleared"}`))
}

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpRPCResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

// requesterRole returns the Grafana org role (Admin/Editor/Viewer) of the
// user who made this request, or "" if unknown (e.g. a request Grafana's own
// backend initiated carries no user) -- attached to every backend request by
// Grafana itself, the same pattern any other app plugin needing
// role-awareness would use.
func requesterRole(ctx context.Context) string {
	user := backend.PluginConfigFromContext(ctx).User
	if user == nil {
		return ""
	}
	return user.Role
}

// requireEditorOrAdmin gates most of what this plugin exposes over its own
// HTTP resource routes to Editor/Admin: every write action (clearing memory,
// toggling RPC Bus/encryption, resetting the encryption key) plus reading
// already-approved fact content (handleFacts), since that content can
// include sensitive incident/runbook detail. A Viewer can open the Brain Hub
// page (see plugin.json's role:"Viewer" on that include), see project names/
// counts and the Pending Suggestions queue, and approve/reject a suggestion
// (handleApprovePendingFact / handleRejectPendingFact -- reviewing an LLM's
// own suggestion requires reading its text, so that one stays open) -- but
// nothing else. Writes 403 and returns false when the caller isn't at least
// Editor; the handler must return immediately in that case.
func requireEditorOrAdmin(w http.ResponseWriter, r *http.Request) bool {
	switch requesterRole(r.Context()) {
	case "Editor", "Admin":
		return true
	default:
		http.Error(w, "Forbidden: this action requires Editor or Admin permissions", http.StatusForbidden)
		return false
	}
}

// requireAdmin gates handleCryptoReset specifically (security-audit finding
// M2): resetting the encryption key/database is disaster recovery, not a
// routine content-management action like clearing memory or toggling a
// setting -- those stay Editor+Admin, this one is Admin-only.
func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if requesterRole(r.Context()) == "Admin" {
		return true
	}
	http.Error(w, "Forbidden: this action requires Admin permissions", http.StatusForbidden)
	return false
}

// requestUser identifies the caller for rate-limiting and audit logging --
// from Grafana's own authenticated plugin context (backend.User.Login), the
// same trustworthy source requesterRole already uses for permission checks.
// Security-audit finding: the client-supplied X-Grafana-User header (used
// here previously) is not authenticated -- live-confirmed a forged value in
// that header landed straight in this plugin's logs and rate-limit bucket
// key, letting a caller spoof audit attribution or evade its own per-user
// limit by rotating the header. Falls back to "anonymous" for a request
// Grafana's own backend initiated, which carries no user.
func requestUser(ctx context.Context) string {
	user := backend.PluginConfigFromContext(ctx).User
	if user == nil || user.Login == "" {
		return "anonymous"
	}
	return user.Login
}

// maxMCPBodyBytes bounds a single tools/call JSON-RPC request -- no
// legitimate memory fact/query needs to be anywhere close to this; without a
// cap here (unlike alerts.go's own 5MB read limit for its outbound calls),
// nothing stopped a caller from sending an arbitrarily large body straight
// into json.Unmarshal.
const maxMCPBodyBytes = 512 * 1024 // 512 KB

func (a *App) handleMCPDirect(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	if len(req.Body) > maxMCPBodyBytes {
		return sender.Send(&backend.CallResourceResponse{
			Status: http.StatusRequestEntityTooLarge,
			Body:   []byte("request body too large"),
		})
	}
	bodyData := req.Body
	isEncrypted := false
	if len(req.Headers["X-Brain-Encryption"]) > 0 && req.Headers["X-Brain-Encryption"][0] == "base64" {
		isEncrypted = true
		if decoded, err := base64.StdEncoding.DecodeString(string(bodyData)); err == nil {
			bodyData = decoded
		}
	}

	var rpcReq mcpRPCRequest
	if err := json.Unmarshal(bodyData, &rpcReq); err != nil {
		return sender.Send(&backend.CallResourceResponse{
			Status: http.StatusBadRequest,
			Body:   []byte("Invalid JSON-RPC request"),
		})
	}

	resp := mcpRPCResponse{
		JSONRPC: "2.0",
		ID:      rpcReq.ID,
	}

	user := requestUser(ctx)

	switch rpcReq.Method {
	case "tools/list":
		resp.Result = handleToolsList()
	case "tools/call":
		// "Flood Protection (Queries/Min)" (BrainConfig.tsx) -- gates real
		// memory operations only, not the cheap tools/list discovery call
		// above. 0/unset (the default) means unlimited, this plugin's
		// original behavior.
		if !a.limiter.allow(user, a.settings.FloodLimitPerMinute) {
			resp.Error = map[string]any{"code": -32000, "message": "rate limit exceeded"}
			body, _ := json.Marshal(resp)
			return sender.Send(&backend.CallResourceResponse{Status: http.StatusTooManyRequests, Body: body})
		}

		// This JSON-RPC path is a side door around the HTTP resource routes'
		// requireEditorOrAdmin gate above. Every tool except suggest_memory
		// (queues a suggestion for admin review, never writes real memory)
		// requires Editor/Admin -- security-audit finding, live-confirmed a
		// Viewer-role token could not only store/delete facts through here
		// with zero role check, but also read every project's fully
		// decrypted memory via search_memory/search_memory_by_time and force
		// a full-table decrypt via brain_diagnostics, none of which were
		// gated at all (only the 4 write/delete tools were). See
		// mcpCallAllowed's doc comment for the one narrow, admin-opt-in
		// exception (TrustedIntegrationLogin) on top of that.
		if !a.mcpCallAllowed(ctx, rpcReq.Params) {
			resp.Error = map[string]any{"code": -32000, "message": "Forbidden: this action requires Editor or Admin permissions"}
			body, _ := json.Marshal(resp)
			return sender.Send(&backend.CallResourceResponse{Status: http.StatusForbidden, Body: body})
		}

		if a.settings.AuditLoggingEnabled {
			a.logger.Info("brain-agent tool call", "user", user, "params", string(rpcReq.Params))
		}

		res, err := a.handleToolsCall(ctx, rpcReq.Params, a.settings)
		if a.settings.AuditLoggingEnabled {
			a.logger.Info("brain-agent tool call result", "user", user, "result", res, "error", err)
		}
		if err != nil {
			resp.Result = map[string]any{
				"isError": true,
				"content": []map[string]any{
					{"type": "text", "text": err.Error()},
				},
			}
		} else {
			resp.Result = map[string]any{
				"isError": false,
				"content": []map[string]any{
					{"type": "text", "text": res},
				},
			}
		}
	default:
		resp.Error = map[string]any{"code": -32601, "message": "Method not found"}
	}

	body, _ := json.Marshal(resp)
	headers := map[string][]string{"Content-Type": {"application/json"}}

	if isEncrypted {
		b64 := base64.StdEncoding.EncodeToString(body)
		body = []byte(b64)
		headers["X-Brain-Encryption"] = []string{"base64"}
	}

	return sender.Send(&backend.CallResourceResponse{
		Status:  http.StatusOK,
		Headers: headers,
		Body:    body,
	})
}

// parseMemoryMetadata builds a *MemoryMetadata from store_memory/
// upsert_memory's optional MCP arguments -- returns nil only when every
// field is genuinely empty/zero, so a plain call with no metadata behaves
// exactly like it did before this feature existed. expiresAt is parsed as
// RFC3339 (ISO8601); an unparseable value is dropped rather than rejecting
// the whole call, since expiry is a nice-to-have, not a correctness
// requirement.
func parseMemoryMetadata(typ, tags, service, namespace, expiresAt string, confidence float64, author string) *MemoryMetadata {
	var expiresAtTime *time.Time
	if expiresAt != "" {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			expiresAtTime = &t
		}
	}
	if typ == "" && tags == "" && service == "" && namespace == "" && confidence == 0 && expiresAtTime == nil && author == "" {
		return nil
	}
	return &MemoryMetadata{
		Type:       typ,
		Tags:       tags,
		Service:    service,
		Namespace:  namespace,
		Confidence: confidence,
		ExpiresAt:  expiresAtTime,
		Author:     author,
	}
}

func handleToolsList() any {
	return map[string]any{
		"tools": []map[string]any{
			{
				"name":        "store_memory",
				"description": "Store important incident facts, solutions, or user preferences in the long-term memory for future use.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fact": map[string]any{
							"type":        "string",
							"description": "The fact or preference to remember",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
						"type": map[string]any{
							"type":        "string",
							"description": "Optional structured category, e.g. 'incident', 'preference', 'runbook'",
						},
						"tags": map[string]any{
							"type":        "string",
							"description": "Optional comma-separated tags",
						},
						"service": map[string]any{
							"type":        "string",
							"description": "Optional service name this fact relates to",
						},
						"namespace": map[string]any{
							"type":        "string",
							"description": "Optional Kubernetes namespace this fact relates to",
						},
						"confidence": map[string]any{
							"type":        "number",
							"description": "Optional confidence 0.0-1.0",
						},
						"expires_at": map[string]any{
							"type":        "string",
							"description": "Optional ISO8601 timestamp after which this fact should be forgotten automatically",
						},
						"author": map[string]any{
							"type":        "string",
							"description": "Optional: the person who curated/confirmed this fact -- most useful for type=\"runbook\" facts (see retrieve_runbook), so a reader knows who to ask about it",
						},
					},
					"required": []string{"fact"},
				},
				"annotations": map[string]any{"readOnlyHint": false},
			},
			{
				"name":        "upsert_memory",
				"description": "Store a fact like store_memory, but skip it if an identical fact (same words, ignoring case/whitespace) is already remembered for this project. Prefer this over store_memory when you might be re-observing something already known (e.g. re-confirming a runbook step, a recurring alert's known cause) to avoid piling up duplicate memories.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fact": map[string]any{
							"type":        "string",
							"description": "The fact or preference to remember",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
						"type": map[string]any{
							"type":        "string",
							"description": "Optional structured category, e.g. 'incident', 'preference', 'runbook'",
						},
						"tags": map[string]any{
							"type":        "string",
							"description": "Optional comma-separated tags",
						},
						"service": map[string]any{
							"type":        "string",
							"description": "Optional service name this fact relates to",
						},
						"namespace": map[string]any{
							"type":        "string",
							"description": "Optional Kubernetes namespace this fact relates to",
						},
						"confidence": map[string]any{
							"type":        "number",
							"description": "Optional confidence 0.0-1.0",
						},
						"expires_at": map[string]any{
							"type":        "string",
							"description": "Optional ISO8601 timestamp after which this fact should be forgotten automatically",
						},
						"author": map[string]any{
							"type":        "string",
							"description": "Optional: the person who curated/confirmed this fact -- most useful for type=\"runbook\" facts (see retrieve_runbook), so a reader knows who to ask about it",
						},
					},
					"required": []string{"fact"},
				},
				"annotations": map[string]any{"readOnlyHint": false},
			},
			{
				"name":        "suggest_memory",
				"description": "Suggest a fact YOU inferred or noticed on your own (not something the user explicitly asked you to remember) for long-term memory. Unlike store_memory/upsert_memory, this does NOT save immediately -- it queues the suggestion for an admin to review and approve from the Brain Hub before it becomes a real, searchable memory. Use store_memory/upsert_memory instead whenever the user explicitly asks you to remember/save something.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fact": map[string]any{
							"type":        "string",
							"description": "The inferred fact being suggested",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{"fact"},
				},
				"annotations": map[string]any{"readOnlyHint": false},
			},
			{
				"name":        "search_memory",
				"description": "Search the long-term memory and RAG runbooks for historical context, similar past incidents, or user preferences.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "The topic or symptom to search for",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{"query"},
				},
				"annotations": map[string]any{"readOnlyHint": true}, // readOnlyHint must be true for agent-ai-app to accept it
			},
			{
				"name":        "delete_memory",
				"description": "Delete a specific fact from the long-term memory if it is outdated, incorrect, or requested by the user.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"fact": map[string]any{
							"type":        "string",
							"description": "The exact fact string to delete",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{"fact"},
				},
				"annotations": map[string]any{"readOnlyHint": false},
			},
			{
				"name":        "brain_diagnostics",
				"description": "Get deep technical diagnostics, health status, telemetry, scaling info, and memory traces of the Brain Agent to answer user questions like 'Is my Brain Agent doing well?'.",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
				"annotations": map[string]any{"readOnlyHint": true},
			},
			{
				"name":        "search_memory_by_time",
				"description": "Temporal RAG (Time-Travel): Search memory facts that were recorded within a specific time range to correlate past events or find out what happened on a specific date.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Optional topic or symptom to search for within the timeframe. Leave empty to get all facts in that range.",
						},
						"start_time": map[string]any{
							"type":        "string",
							"description": "Start time in ISO8601 format (e.g., '2026-07-20T00:00:00Z')",
						},
						"end_time": map[string]any{
							"type":        "string",
							"description": "End time in ISO8601 format (e.g., '2026-07-21T23:59:59Z')",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{"start_time", "end_time"},
				},
				"annotations": map[string]any{"readOnlyHint": true},
			},
			{
				"name":        "retrieve_runbook",
				"description": "Retrieve curated, approved runbook facts (type=\"runbook\") for a project -- restricted to that type and status=\"approved\" so only reviewed, trusted procedures are returned, not any old chat observation that happened to get remembered. Use this instead of search_memory when you specifically want a runbook/procedure, not any memory fact.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"query": map[string]any{
							"type":        "string",
							"description": "Optional topic/symptom to filter and rank runbooks by. Leave empty to get the most recent runbooks.",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{},
				},
				"annotations": map[string]any{"readOnlyHint": true},
			},
			{
				"name":        "condense_memory",
				"description": "Distill and condense multiple similar/older facts into a single 'Golden Record' runbook. This keeps the memory clean. Supply the new condensed fact and an array of the exact old facts to delete.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"condensed_fact": map[string]any{
							"type":        "string",
							"description": "The new consolidated and summarized fact that replaces the old ones",
						},
						"facts_to_delete": map[string]any{
							"type": "array",
							"items": map[string]any{
								"type": "string",
							},
							"description": "Array of exact old facts to be deleted",
						},
						"project": map[string]any{
							"type":        "string",
							"description": "Optional project or tenancy context (default: 'default')",
						},
					},
					"required": []string{"condensed_fact", "facts_to_delete"},
				},
				"annotations": map[string]any{"readOnlyHint": false},
			},
		},
	}
}

// viewerSafeMCPTools is the only tools/call name a Viewer may invoke.
// suggest_memory never writes real memory -- it queues a suggestion for
// admin review (same as the HTTP approve/reject routes above). Every other
// tool, including reads like search_memory/search_memory_by_time/
// brain_diagnostics, requires Editor/Admin (or the narrow
// trustedIntegrationReadOnlyTools exception below).
//
// This used to be an inverted allowlist of only the mutating (write/delete)
// tools, gating writes but leaving every read open to Viewer -- a live,
// security-audit-confirmed bypass: search_memory and search_memory_by_time
// return full decrypted memory content to any Viewer, and brain_diagnostics
// decrypts the entire memory_store table in memory on every call, neither
// gated at all. Defaulting to deny (an allowlist of what a Viewer CAN do)
// instead of an allowlist of what to block means a newly-added tool is
// Editor/Admin-only by default, not silently exposed to Viewer.
var viewerSafeMCPTools = map[string]bool{
	"suggest_memory": true,
}

// trustedIntegrationReadOnlyTools are the only tools Settings.
// TrustedIntegrationLogin's identity may call while at Viewer role (see
// mcpCallAllowed) -- every write/delete tool is deliberately excluded, so
// that identity still needs real Editor/Admin for those regardless of this
// setting. Kept as its own map (not merged into viewerSafeMCPTools) so the
// two exceptions -- "any Viewer" vs. "this one named identity" -- can never
// be confused at a glance.
var trustedIntegrationReadOnlyTools = map[string]bool{
	"search_memory":         true,
	"search_memory_by_time": true,
	"brain_diagnostics":     true,
	"retrieve_runbook":      true,
}

// mcpToolName extracts a tools/call request's target tool name. Empty on
// malformed/unparseable params -- callers must treat "" as matching nothing
// in either allowlist (fail closed).
func mcpToolName(params json.RawMessage) string {
	var args struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return ""
	}
	return args.Name
}

// mcpCallAllowed decides whether one tools/call request may proceed.
// Editor/Admin can call anything; a Viewer can only call
// viewerSafeMCPTools; and Settings.TrustedIntegrationLogin -- if the admin
// set it -- gets one narrow additional exception for
// trustedIntegrationReadOnlyTools only.
//
// Why this exists: brain-agent's own security fix here (see
// viewerSafeMCPTools' doc comment) closed a real RBAC bypass by requiring
// Editor/Admin for every read tool. But agent-ai-app's integration calls
// these same tools through a single shared Grafana service account that is
// deliberately kept at Viewer (see deploy/operator/serviceaccount.yaml --
// giving it Editor would let every chat user act with Editor-level access
// through that SA, regardless of their own real Grafana role, the exact
// privilege escalation H-01 closed). Combined, those two correct decisions
// meant the integration could no longer read any stored memory at all --
// only suggest_memory (queue a suggestion) still worked.
//
// TrustedIntegrationLogin lets an admin name ONE specific, already-
// provisioned identity (typically that same service account's own Grafana
// login) as trusted for read-only tools specifically, without reopening
// read access to Viewer role in general. requestUser(ctx) resolves this
// from backend.PluginConfigFromContext, the same Grafana-authenticated
// source requesterRole already trusts for every other permission check in
// this file -- never a client-supplied header, which was H-01's actual
// bug. An attacker would need to already be authenticated as that exact
// identity (hold its real token) to match, at which point they have that
// SA's access either way -- this doesn't create a new way to obtain it,
// only a new thing that identity can do once obtained. Empty/unset (the
// default) keeps the existing Editor/Admin-only behavior for every
// Viewer-role caller; this is opt-in, not a default relaxation.
func (a *App) mcpCallAllowed(ctx context.Context, params json.RawMessage) bool {
	name := mcpToolName(params)
	if viewerSafeMCPTools[name] {
		return true
	}
	switch requesterRole(ctx) {
	case "Editor", "Admin":
		return true
	}
	return a.settings.TrustedIntegrationLogin != "" &&
		trustedIntegrationReadOnlyTools[name] &&
		requestUser(ctx) == a.settings.TrustedIntegrationLogin
}

func (a *App) handleToolsCall(ctx context.Context, params json.RawMessage, settings Settings) (string, error) {
	var args struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		return "", err
	}

	switch args.Name {
	case "store_memory":
		var m struct {
			Fact       string  `json:"fact"`
			Project    string  `json:"project"`
			Type       string  `json:"type"`
			Tags       string  `json:"tags"`
			Service    string  `json:"service"`
			Namespace  string  `json:"namespace"`
			Confidence float64 `json:"confidence"`
			ExpiresAt  string  `json:"expires_at"`
			Author     string  `json:"author"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}
		if err := a.StoreMemoryWithMetadata(ctx, m.Project, m.Fact, parseMemoryMetadata(m.Type, m.Tags, m.Service, m.Namespace, m.ExpiresAt, m.Confidence, m.Author)); err != nil {
			return "", fmt.Errorf("failed to store memory: %w", err)
		}
		return fmt.Sprintf("Successfully stored in memory for project '%s': %s", m.Project, m.Fact), nil

	case "upsert_memory":
		var m struct {
			Fact       string  `json:"fact"`
			Project    string  `json:"project"`
			Type       string  `json:"type"`
			Tags       string  `json:"tags"`
			Service    string  `json:"service"`
			Namespace  string  `json:"namespace"`
			Confidence float64 `json:"confidence"`
			ExpiresAt  string  `json:"expires_at"`
			Author     string  `json:"author"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}
		inserted, err := a.UpsertMemoryWithMetadata(ctx, m.Project, m.Fact, parseMemoryMetadata(m.Type, m.Tags, m.Service, m.Namespace, m.ExpiresAt, m.Confidence, m.Author))
		if err != nil {
			return "", fmt.Errorf("failed to upsert memory: %w", err)
		}
		if !inserted {
			return fmt.Sprintf("Already remembered for project '%s' -- no duplicate stored: %s", m.Project, m.Fact), nil
		}
		return fmt.Sprintf("Successfully stored in memory for project '%s': %s", m.Project, m.Fact), nil

	case "suggest_memory":
		var m struct {
			Fact    string `json:"fact"`
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}
		if err := a.SuggestMemory(ctx, m.Project, m.Fact); err != nil {
			return "", fmt.Errorf("failed to suggest memory: %w", err)
		}
		return fmt.Sprintf("Suggestion queued for admin review in project '%s': %s", m.Project, m.Fact), nil

	case "search_memory":
		var m struct {
			Query   string `json:"query"`
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}

		results, err := a.SearchMemory(ctx, m.Project, m.Query, isEnabled(settings.SemanticSearchEnabled))
		if err != nil {
			return "", fmt.Errorf("failed to search memory: %w", err)
		}

		// Strict Tenancy off means a project with nothing of its own can
		// still see shared/global facts stored under "default" -- strict
		// tenancy stays the default (nil == true, see Settings), so this
		// never runs unless an admin explicitly opted out of isolation.
		if len(results) == 0 && !isEnabled(settings.StrictTenancyEnabled) && m.Project != "" && m.Project != "default" {
			fallback, fallbackErr := a.SearchMemory(ctx, "default", m.Query, isEnabled(settings.SemanticSearchEnabled))
			if fallbackErr == nil {
				results = fallback
			}
		}

		if len(results) == 0 {
			return "Memory is currently empty or no matches found.", nil
		}

		result := fmt.Sprintf("Here are the relevant historical facts from memory (Project: %s):\n", m.Project)
		for i, fact := range results {
			result += fmt.Sprintf("- [%d] %s\n", i, fact)
		}
		return result, nil

	case "search_memory_by_time":
		var m struct {
			Query     string `json:"query"`
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			Project   string `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}

		results, err := a.SearchMemoryByTime(ctx, m.Project, m.Query, m.StartTime, m.EndTime)
		if err != nil {
			return "", fmt.Errorf("failed to search memory by time: %w", err)
		}

		if len(results) == 0 {
			return fmt.Sprintf("No matches found between %s and %s.", m.StartTime, m.EndTime), nil
		}

		result := fmt.Sprintf("Temporal RAG Matches (Project: %s, From: %s, To: %s):\n", m.Project, m.StartTime, m.EndTime)
		for i, fact := range results {
			result += fmt.Sprintf("- [%d] %s\n", i, fact)
		}
		return result, nil

	case "retrieve_runbook":
		var m struct {
			Query   string `json:"query"`
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}

		records, err := a.RetrieveRunbook(ctx, m.Project, m.Query)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve runbook: %w", err)
		}

		if len(records) == 0 {
			return fmt.Sprintf("No approved runbooks found for project '%s'.", m.Project), nil
		}

		result := fmt.Sprintf("Approved runbooks (Project: %s):\n", m.Project)
		for i, r := range records {
			result += fmt.Sprintf("- [%d] %s", i, r.Fact)
			if r.Author != "" {
				result += fmt.Sprintf(" (author: %s)", r.Author)
			}
			result += "\n"
		}
		return result, nil

	case "condense_memory":
		var m struct {
			CondensedFact string   `json:"condensed_fact"`
			FactsToDelete []string `json:"facts_to_delete"`
			Project       string   `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}
		if err := a.CondenseMemory(ctx, m.Project, m.CondensedFact, m.FactsToDelete); err != nil {
			return "", fmt.Errorf("failed to condense memory: %w", err)
		}
		return fmt.Sprintf("Successfully condensed %d old facts into 1 golden record for project '%s'.", len(m.FactsToDelete), m.Project), nil

	case "delete_memory":
		var m struct {
			Fact    string `json:"fact"`
			Project string `json:"project"`
		}
		if err := json.Unmarshal(args.Arguments, &m); err != nil {
			return "", err
		}
		if err := a.DeleteMemory(ctx, m.Project, m.Fact); err != nil {
			return "", fmt.Errorf("failed to delete memory: %w", err)
		}
		return fmt.Sprintf("Successfully deleted memory for project '%s': %s", m.Project, m.Fact), nil

	case "brain_diagnostics":
		// Every field below is a real, measured value -- this tool used to
		// return hardcoded claims ("GREEN", "< 5ms avg", "no anomalies
		// detected") regardless of actual state, which is worse than not
		// having a diagnostics tool at all: a confidently wrong health
		// report.
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		queryStart := time.Now()
		stats, statsErr := a.GetProjectStats(ctx)
		queryDuration := time.Since(queryStart)
		totalFacts := 0
		for _, count := range stats {
			totalFacts += count
		}

		dbStatus := "ok"
		if pingErr := a.PingDB(); pingErr != nil {
			dbStatus = fmt.Sprintf("error: %v", pingErr)
		} else if statsErr != nil {
			dbStatus = fmt.Sprintf("error: %v", statsErr)
		}

		dbSizeMB := float64(-1)
		if info, err := os.Stat(a.dbFilePath); err == nil {
			dbSizeMB = float64(info.Size()) / 1024 / 1024
		}

		duplicateFacts, dupErr := a.CountDuplicateFacts(ctx)
		decryptFailures, lastDecryptFailureAt := a.decryptFailureStats()
		autoLearnStarted, autoLearnLastPollAt, autoLearnLastErr := a.autoLearnStatus()

		autoLearn := map[string]any{"enabled": autoLearnStarted}
		if autoLearnStarted {
			autoLearn["last_poll_at"] = autoLearnLastPollAt.UTC().Format(time.RFC3339)
			if autoLearnLastErr != "" {
				autoLearn["last_error"] = autoLearnLastErr
			}
		}

		duplicatesField := any(duplicateFacts)
		if dupErr != nil {
			duplicatesField = fmt.Sprintf("error: %v", dupErr)
		}

		diag := map[string]any{
			"database": map[string]any{
				"status":            dbStatus,
				"file_size_mb":      dbSizeMB,
				"total_facts":       totalFacts,
				"active_projects":   len(stats),
				"duplicate_facts":   duplicatesField,
				"stats_query_ms":    queryDuration.Milliseconds(),
				"max_size_mb_limit": a.maintenanceMaxDbSizeMB,
				"retention_days":    a.maintenanceRetentionDays,
			},
			"encryption": map[string]any{
				"decrypt_failures_total": decryptFailures,
			},
			"auto_learn_alerts": autoLearn,
			"process": map[string]any{
				"goroutines":   runtime.NumGoroutine(),
				"allocated_mb": mem.Alloc / 1024 / 1024,
				"sys_mb":       mem.Sys / 1024 / 1024,
			},
		}
		if decryptFailures > 0 {
			diag["encryption"].(map[string]any)["last_failure_at"] = lastDecryptFailureAt.UTC().Format(time.RFC3339)
		}

		b, _ := json.MarshalIndent(diag, "", "  ")
		return string(b), nil

	default:
		return "", fmt.Errorf("unknown tool %s", args.Name)
	}
}
