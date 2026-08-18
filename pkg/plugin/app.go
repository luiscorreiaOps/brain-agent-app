package plugin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/backend/instancemgmt"
	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
	"github.com/grafana/grafana-plugin-sdk-go/backend/resource/httpadapter"
)

// Settings configures brain-agent's own behavior -- everything here is
// read/written via Grafana's native plugin settings endpoint
// (/api/plugins/brain-agent/settings), the same one every other app plugin
// in this repo uses; there is no brain-agent-specific settings API.
type Settings struct {
	// SemanticSearchEnabled gates SearchMemory's TF-IDF-lite relevance
	// scoring (see db.go). nil defaults to true (existing behavior) --
	// when explicitly false, search_memory returns the most recent facts
	// instead of scoring, which is cheaper and more predictable for
	// projects with few, mostly-chronological facts.
	SemanticSearchEnabled *bool `json:"semanticSearchEnabled,omitempty"`
	// StrictTenancyEnabled gates whether search_memory ever looks outside
	// the requested project. nil defaults to true (strict isolation,
	// existing behavior). When explicitly false, a query that finds
	// nothing in its own project also falls back to the "default" project
	// -- useful for a single-tenant/global knowledge base setup where
	// callers don't always pass a project_id.
	StrictTenancyEnabled *bool `json:"strictTenancyEnabled,omitempty"`
	// AutoLearnAlerts, when true (and GrafanaURL/GrafanaToken below are
	// both set), starts a background poller that turns newly-resolved
	// Grafana alerts into stored memories automatically -- see alerts.go.
	// This is the only automatic (non-explicit-tool-call) path into
	// StoreMemory that exists in this plugin.
	AutoLearnAlerts bool `json:"autoLearnAlerts,omitempty"`
	// GrafanaURL is this Grafana instance's own base URL, needed to poll
	// its alerting API. Typically http://localhost:3000 from inside the
	// Grafana pod/container itself.
	GrafanaURL string `json:"grafanaURL,omitempty"`
	// GrafanaToken is a Grafana service account token with at least
	// Viewer access, needed to read the alerting API. Read from
	// secureJsonData, never serialized back out.
	GrafanaToken string `json:"-"`

	// The fields below back BrainConfig.tsx's Storage & Database / RAG /
	// Compliance sections -- until this pass they were typed into the form
	// and never read anywhere in this package (a real, confirmed bug: an
	// admin changing them had no effect at all). 0/false keeps this
	// plugin's original hardcoded behavior exactly.
	MaxMemories         int     `json:"maxMemories,omitempty"`
	RagOverlapThreshold float64 `json:"ragOverlapThreshold,omitempty"`
	RetentionDays       int     `json:"retentionDays,omitempty"`
	FloodLimitPerMinute int     `json:"floodLimitPerMinute,omitempty"`
	MaxDbSizeMB         int     `json:"maxDbSizeMB,omitempty"`
	AuditLoggingEnabled bool    `json:"auditLoggingEnabled,omitempty"`

	// AtRestEncryptionEnabled gates whether a NEW fact is encrypted
	// (AES-256-GCM) before being written to disk. false (the Go zero value)
	// by default -- an admin must explicitly opt in, per explicit request;
	// this used to be an always-on, non-optional behavior with a fake
	// toggle in the UI (see BrainHub.tsx's git history) -- now the toggle
	// is real and actually gates it. Already-stored facts are unaffected
	// either way: is_encrypted is a per-row flag set at write time, not a
	// global switch, so flipping this setting never re-encrypts or
	// decrypts anything already on disk (see db.go's StoreMemory/
	// CondenseMemory and decryptTrackingFailures).
	AtRestEncryptionEnabled bool `json:"atRestEncryptionEnabled,omitempty"`

	// InTransitEncryptionEnabled gates the "RPC Bus" toggle: whether MCP
	// request/response bodies exchanged with agent-ai-app are base64-encoded
	// (not real encryption -- transport obfuscation, see mcp.go). Used to
	// live in a /tmp sentinel file both plugins read directly off the
	// shared pod filesystem -- didn't survive a pod restart and wasn't safe
	// with more than one replica (security-audit finding M3). Now real
	// plugin settings, same as every other toggle here.
	InTransitEncryptionEnabled bool `json:"inTransitEncryptionEnabled,omitempty"`

	// PIIDetectionEnabled gates whether a new fact is scanned by detectPII
	// (pii.go) at write time. false (the Go zero value) by default -- same
	// explicit-opt-in convention as AtRestEncryptionEnabled just above, per
	// explicit request: an admin turns on the extra scanning on every
	// store_memory/upsert_memory/suggest_memory call from BrainConfig.tsx's
	// Compliance & Auditing section, it isn't assumed.
	PIIDetectionEnabled bool `json:"piiDetectionEnabled,omitempty"`

	// EmbeddingEndpointURL/EmbeddingModel configure a real semantic-search
	// backend for search_memory (see embeddings.go) -- an OpenAI-compatible
	// /embeddings endpoint (Ollama, OpenAI, or a compatible gateway).
	// Empty/unset (the default) keeps search_memory's existing lexical
	// ("TF-IDF-lite") scoring exactly as it was before this feature
	// existed; this is a genuinely optional upgrade, not a required
	// dependency.
	EmbeddingEndpointURL string `json:"embeddingEndpointURL,omitempty"`
	EmbeddingModel       string `json:"embeddingModel,omitempty"`
	// EmbeddingAPIKey is read from secureJsonData, never serialized back out.
	EmbeddingAPIKey string `json:"-"`

	// EncryptionKey, when set, is a base64-encoded 32-byte AES-256 key
	// used directly instead of generating/reading brain_aes.key from the
	// data directory (security-audit finding L3: a key stored in the same
	// directory as the database it protects means anyone with a copy of
	// that directory -- e.g. a backup -- has both the lock and the key).
	// Read from secureJsonData (Grafana encrypts it at rest), never
	// serialized back out. Empty/unset (the default) keeps the existing
	// local-file behavior exactly as before -- this is opt-in, not a
	// required migration for existing installs.
	EncryptionKey string `json:"-"`

	// TrustedIntegrationLogin, when set, is the Grafana login of one
	// specific, already-provisioned identity (typically agent-ai-app's own
	// service account -- see deploy/operator/serviceaccount.yaml) allowed
	// to call brain-agent's read-only MCP tools (search_memory/
	// search_memory_by_time/brain_diagnostics) even while that identity's
	// Grafana role is Viewer. See resources.go's mcpCallAllowed for the
	// full reasoning -- this does not grant write/delete access, and does
	// not affect any other Viewer. Empty/unset (the default) keeps every
	// Viewer-role caller Editor/Admin-gated for these tools, same as
	// before this field existed -- this is opt-in.
	TrustedIntegrationLogin string `json:"trustedIntegrationLogin,omitempty"`
}

func isEnabled(flag *bool) bool {
	return flag == nil || *flag
}

// App is the Grafana app plugin instance for brain-agent
type App struct {
	logger   log.Logger
	mux      *http.ServeMux
	settings Settings
	limiter  *perUserRateLimiter

	stopAutoLearn context.CancelFunc

	// --- security-audit finding H8 ---
	// A Grafana app-plugin backend (backend=true) can host more than one App
	// instance in the SAME OS process at once -- one per organization (see
	// instancemgmt.Instance). Every field below used to be a package-level
	// var in db.go/crypto.go/search_index.go/embeddings.go/alerts.go, which
	// meant a second org's App instance silently shared (and could overwrite
	// mid-request) the first org's database handle, encryption keys, and
	// settings-derived toggles. Migrated here so each App instance owns its
	// own copy, the same way `settings` already does.

	db         *sql.DB
	dbFilePath string

	// orgID is the org this specific App instance was created for (read once
	// in NewApp from the request ctx that triggered its creation -- see
	// dbNameForOrg). The per-instance fields above already stopped one org's
	// App instance from sharing Go-level state with another's; they did NOT
	// stop every org's instance from opening the exact same SQLite file on
	// disk, since the filename only ever depended on the plugin's install
	// directory name, never on which org asked for it. That was the actual
	// remaining gap in H8: two orgs on the same Grafana got two separate App
	// structs, but both structs' *sql.DB pointed at one shared brain-agent.db
	// -- one org's memories, searches, and pending facts were all readable
	// and writable by the other. orgID 1 (Grafana's default org) keeps the
	// original unsuffixed filename so existing single-org installs need no
	// migration; every other org gets its own "<pluginDirName>-org<N>.db".
	orgID int64

	aesKey  []byte
	hmacKey []byte

	maintenanceMaxDbSizeMB     int
	maintenanceRetentionDays   int
	maintenanceMaxResults      int
	maintenanceMinOverlapRatio float64

	decryptFailureMu     sync.Mutex
	decryptFailureCount  int
	lastDecryptFailureAt time.Time

	atRestEncryptionEnabled bool
	piiDetectionEnabled     bool

	embeddingEndpointURL string
	embeddingModel       string
	embeddingAPIKey      string

	maintenanceStopMu      sync.Mutex
	currentMaintenanceStop func()

	duplicateFactsCacheMu   sync.Mutex
	duplicateFactsCacheVal  int
	duplicateFactsCacheTime time.Time

	autoLearnStatusMu    sync.Mutex
	autoLearnLastPollAt  time.Time
	autoLearnLastError   string
	autoLearnEverStarted bool
}

// detectPluginDirName returns the name of the directory this plugin's own
// backend binary is installed into -- "brain-agent" for a normal install,
// something else for a forked/rebranded one. Both NewApp (to name the real
// DB file, see InitDB) and handleCryptoReset (to back up/reset that same
// file) need this, and must agree -- they used to disagree (the reset
// endpoint had "brain-agent" hardcoded), which silently broke on a fork.
func detectPluginDirName() string {
	execPath, err := os.Executable()
	if err != nil {
		return "brain-agent"
	}
	return filepath.Base(filepath.Dir(execPath))
}

// cryptoResetPaths returns the exact key/db file paths handleCryptoReset
// backs up and re-initializes -- a pure function of dataDir, the already
// -detected plugin directory name (as dbName, already org-suffixed by the
// caller), and orgID (to suffix the two key paths the same way), kept
// separate from detectPluginDirName's os.Executable() call so it's trivially
// testable with an arbitrary name (a real test can't control what
// os.Executable() reports for the test binary itself).
func cryptoResetPaths(dataDir, dbName string, orgID int64) (keyPath, hmacKeyPath, dbPath string) {
	return filepath.Join(dataDir, fmt.Sprintf("%s.key", orgSuffixedName("brain_aes", orgID))),
		filepath.Join(dataDir, fmt.Sprintf("%s.key", orgSuffixedName("brain_hmac", orgID))),
		filepath.Join(dataDir, fmt.Sprintf("%s.db", dbName))
}

// orgSuffixedName returns the filename base (without extension) this App
// instance should use for a given base name -- the plugin directory name for
// the SQLite database, or "brain_aes"/"brain_hmac" for the two encryption
// keys (see InitCrypto/InitSearchIndexKey). orgID 1 is Grafana's default/only
// org on a single-org install -- kept unsuffixed for zero-migration backward
// compatibility with every install that predates per-org isolation. Every
// other org gets its own file, so two orgs sharing one Grafana never share
// rows OR key material (security-audit finding H8's remaining gap: see the
// orgID field comment on App). Sharing key material mattered just as much as
// sharing the database: before this, any org's Admin could hit /crypto/reset
// and rotate the one shared brain_aes.key/brain_hmac.key, permanently
// orphaning every OTHER org's already-encrypted rows -- a cross-org denial of
// service through an action that only touched their own org's settings.
func orgSuffixedName(base string, orgID int64) string {
	if orgID <= 1 {
		return base
	}
	return fmt.Sprintf("%s-org%d", base, orgID)
}

func orgIDFromContext(ctx context.Context) int64 {
	// Keep the numeric org id for the existing per-org database/key naming
	// scheme. Migrating this to PluginContext.Namespace needs an explicit
	// filename migration so existing installs do not lose their stored memory.
	//nolint:staticcheck
	return backend.PluginConfigFromContext(ctx).OrgID
}

// NewApp creates a new App instance. Grafana's plugin SDK already creates one
// App instance per org (see instancemgmt.Instance / instanceProvider.NewInstance
// in grafana-plugin-sdk-go), cached by "pluginID#orgID" -- ctx here is
// guaranteed to carry the triggering request's PluginContext (with OrgID),
// since instance creation only ever happens lazily, inline with the first
// real CallResource/QueryData/CheckHealth request for that org, and
// MiddlewareHandler embeds PluginContext into ctx before any of those reach
// the code that creates the instance.
func NewApp(ctx context.Context, appSettings backend.AppInstanceSettings) (instancemgmt.Instance, error) {
	orgID := orgIDFromContext(ctx)

	app := &App{
		orgID:   orgID,
		logger:  log.DefaultLogger.With("plugin", "brain-agent"),
		limiter: newPerUserRateLimiter(),
		// Matches this plugin's original hardcoded behavior (500MB cap, no
		// day-based retention, 50-result cap, no overlap filtering) --
		// configureMaintenance below only overrides values the admin
		// actually configured (>0).
		maintenanceMaxDbSizeMB: 500,
		maintenanceMaxResults:  50,
	}

	var settings Settings
	if len(appSettings.JSONData) > 0 {
		if err := json.Unmarshal(appSettings.JSONData, &settings); err != nil {
			app.logger.Error("Failed to unmarshal settings, using defaults", "error", err)
			settings = Settings{}
		}
	}
	settings.GrafanaURL = strings.TrimSpace(settings.GrafanaURL)
	if grafanaToken, ok := appSettings.DecryptedSecureJSONData["grafanaToken"]; ok {
		settings.GrafanaToken = strings.TrimSpace(grafanaToken)
	}
	if embeddingAPIKeyVal, ok := appSettings.DecryptedSecureJSONData["embeddingAPIKey"]; ok {
		settings.EmbeddingAPIKey = strings.TrimSpace(embeddingAPIKeyVal)
	}
	if encryptionKeyVal, ok := appSettings.DecryptedSecureJSONData["encryptionKey"]; ok {
		settings.EncryptionKey = strings.TrimSpace(encryptionKeyVal)
	}
	app.settings = settings
	app.configureMaintenance(settings.MaxDbSizeMB, settings.RetentionDays, settings.MaxMemories, settings.RagOverlapThreshold)
	app.atRestEncryptionEnabled = settings.AtRestEncryptionEnabled
	app.piiDetectionEnabled = settings.PIIDetectionEnabled
	app.embeddingEndpointURL = strings.TrimSpace(settings.EmbeddingEndpointURL)
	app.embeddingModel = strings.TrimSpace(settings.EmbeddingModel)
	app.embeddingAPIKey = settings.EmbeddingAPIKey

	pluginDirName := detectPluginDirName()
	dbName := orgSuffixedName(pluginDirName, orgID)

	// Initialize the SQLite DB in Grafana's own data directory, using the
	// plugin directory name (plus an org suffix for every org but the
	// default one, see dbNameForOrg) to isolate databases.
	if err := app.InitDB("/var/lib/grafana", dbName, settings.EncryptionKey); err != nil {
		app.logger.Error("Failed to initialize SQLite database", "error", err)
	}

	app.registerRoutes()

	if settings.AutoLearnAlerts && settings.GrafanaURL != "" && settings.GrafanaToken != "" {
		autoLearnCtx, cancel := context.WithCancel(context.Background())
		app.stopAutoLearn = cancel
		app.startAutoLearnAlerts(autoLearnCtx, settings.GrafanaURL, settings.GrafanaToken)
	}

	return app, nil
}

// CheckHealth checks if the plugin is running properly
// CheckHealth used to always report HealthStatusOk regardless of the
// database's actual state (security-audit finding M1) -- NewApp only logs
// an InitDB failure and continues, so a broken database could sit behind
// an always-green health check indefinitely. The HTTP /health route
// already correctly called PingDB; the SDK's own CheckHealth (what Grafana
// itself surfaces in the plugin health UI) did not.
func (a *App) CheckHealth(ctx context.Context, req *backend.CheckHealthRequest) (*backend.CheckHealthResult, error) {
	if err := a.PingDB(); err != nil {
		return &backend.CheckHealthResult{
			Status:  backend.HealthStatusError,
			Message: fmt.Sprintf("database not reachable: %v", err),
		}, nil
	}
	return &backend.CheckHealthResult{
		Status:  backend.HealthStatusOk,
		Message: "Brain Agent is running",
	}, nil
}

func (a *App) Dispose() {
	if a.stopAutoLearn != nil {
		a.stopAutoLearn()
	}
	a.StopHealthMaintenance()
}

// CallResource forwards API calls
func (a *App) CallResource(ctx context.Context, req *backend.CallResourceRequest, sender backend.CallResourceResponseSender) error {
	a.logger.Info("CallResource received", "path", req.Path, "method", req.Method)

	if req.Path == "mcp" && req.Method == http.MethodPost {
		return a.handleMCPDirect(ctx, req, sender)
	}

	adapter := httpadapter.New(a.mux)
	return adapter.CallResource(ctx, req, sender)
}
