package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

func mustParseRFC3339(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("failed to parse time %q: %v", s, err)
	}
	return tm
}

// alertsHandler serves the Alertmanager-v2-shaped alert list this plugin
// polls, keyed by which alertnames should currently be reported as firing.
func alertsHandler(t *testing.T, firing []string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || q.Get("active") != "true" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		alerts := make([]gettableAlert, 0, len(firing))
		for _, name := range firing {
			alerts = append(alerts, gettableAlert{
				Labels:      map[string]string{"alertname": name, "namespace": "dev"},
				Annotations: map[string]string{"summary": name + " is firing"},
				Fingerprint: name,
				Status: struct {
					State string `json:"state"`
				}{State: "active"},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(alerts)
	}
}

func TestPollOnce_StoresMemoryWhenAlertStopsFiring(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-alerts-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	app := &App{logger: log.NewNullLogger(), maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	t.Cleanup(app.resetAutoLearnStatus)
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// First poll: HighCPU is firing.
	server := httptest.NewServer(alertsHandler(t, []string{"HighCPU"}))
	defer server.Close()

	client := &http.Client{}

	firing := app.pollOnce(context.Background(), client, server.URL, "token", map[string]gettableAlert{})
	if len(firing) != 1 {
		t.Fatalf("firing = %+v, want 1 entry seeded from the first poll", firing)
	}

	results, err := app.SearchMemory(context.Background(), "dev", "HighCPU", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want no memory stored yet -- an alert still firing must not be recorded as resolved", results)
	}

	// Second poll: HighCPU is no longer in the firing list -- it resolved.
	server2 := httptest.NewServer(alertsHandler(t, []string{}))
	defer server2.Close()

	firing = app.pollOnce(context.Background(), client, server2.URL, "token", firing)
	if len(firing) != 0 {
		t.Errorf("firing = %+v, want empty after the alert resolved", firing)
	}

	results, err = app.SearchMemory(context.Background(), "dev", "HighCPU", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly one stored memory for the now-resolved alert", results)
	}
	if !strings.Contains(results[0], "HighCPU") || !strings.Contains(results[0], "resolved") {
		t.Errorf("stored fact = %q, want it to mention the alert name and that it resolved", results[0])
	}
}

func TestPollOnce_StillFiringAlertIsNotStored(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "brain-agent-alerts-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	app := &App{logger: log.NewNullLogger(), maintenanceMaxDbSizeMB: 500, maintenanceMaxResults: 50}
	t.Cleanup(app.resetAutoLearnStatus)
	if err := app.InitDB(tempDir, "brain-agent", ""); err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	server := httptest.NewServer(alertsHandler(t, []string{"HighCPU"}))
	defer server.Close()
	client := &http.Client{}

	firing := app.pollOnce(context.Background(), client, server.URL, "token", map[string]gettableAlert{})
	// Poll again against the same still-firing alert.
	firing = app.pollOnce(context.Background(), client, server.URL, "token", firing)
	if len(firing) != 1 {
		t.Errorf("firing = %+v, want the alert to remain tracked as firing", firing)
	}

	results, err := app.SearchMemory(context.Background(), "dev", "HighCPU", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want nothing stored -- the alert never stopped firing", results)
	}
}

func TestResolvedAlertFact_IncludesLabelsRunbookAndDashboardLink(t *testing.T) {
	endsAt := mustParseRFC3339(t, "2026-07-20T10:00:00Z")
	a := gettableAlert{
		Labels: map[string]string{
			"alertname": "HighCPU", "namespace": "prod", "service": "checkout", "severity": "critical",
		},
		Annotations: map[string]string{
			"summary":          "CPU usage above threshold",
			"runbook_url":      "https://runbooks.example.com/high-cpu",
			"__dashboardUid__": "abc123",
			"__panelId__":      "7",
		},
		EndsAt: endsAt,
	}

	fact := resolvedAlertFact(a)

	for _, want := range []string{
		`Alert "HighCPU" resolved at 2026-07-20T10:00:00Z`,
		"CPU usage above threshold",
		"namespace=prod", "service=checkout", "severity=critical",
		"Runbook: https://runbooks.example.com/high-cpu",
		"Dashboard: /d/abc123?viewPanel=7",
	} {
		if !strings.Contains(fact, want) {
			t.Errorf("fact = %q, want it to contain %q", fact, want)
		}
	}
}

func TestResolvedAlertFact_FallsBackToNowWhenEndsAtMissing(t *testing.T) {
	a := gettableAlert{Labels: map[string]string{"alertname": "NoEndsAt"}}
	fact := resolvedAlertFact(a)
	if !strings.Contains(fact, `Alert "NoEndsAt" resolved at`) {
		t.Errorf("fact = %q, want it to still mention resolution even with no EndsAt", fact)
	}
}

func TestAlertDashboardLink_PrefersDashboardAnnotationsOverGeneratorURL(t *testing.T) {
	a := gettableAlert{
		Annotations:  map[string]string{"__dashboardUid__": "xyz"},
		GeneratorURL: "https://grafana.example.com/alerting/rule/edit",
	}
	if link := alertDashboardLink(a); link != "/d/xyz" {
		t.Errorf("alertDashboardLink = %q, want \"/d/xyz\" (dashboard annotation preferred over GeneratorURL)", link)
	}

	fallback := gettableAlert{GeneratorURL: "https://grafana.example.com/alerting/rule/edit"}
	if link := alertDashboardLink(fallback); link != "https://grafana.example.com/alerting/rule/edit" {
		t.Errorf("alertDashboardLink = %q, want the raw GeneratorURL when no dashboard annotation exists", link)
	}
}

func TestPollOnce_StoresStructuredMetadataForResolvedAlert(t *testing.T) {
	app := newTestDB(t)
	t.Cleanup(app.resetAutoLearnStatus)

	server := httptest.NewServer(alertsHandler(t, []string{"HighCPU"}))
	defer server.Close()
	client := &http.Client{}

	firing := app.pollOnce(context.Background(), client, server.URL, "token", map[string]gettableAlert{})

	server2 := httptest.NewServer(alertsHandler(t, []string{}))
	defer server2.Close()
	app.pollOnce(context.Background(), client, server2.URL, "token", firing)

	records, err := app.ListFactsWithMetadata(context.Background(), "dev")
	if err != nil {
		t.Fatalf("ListFactsWithMetadata failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	r := records[0]
	if r.Type != "incident" || r.Source != "auto-learn-alerts" || r.Namespace != "dev" {
		t.Errorf("record = %+v, want type=incident source=auto-learn-alerts namespace=dev", r)
	}
}

func TestFetchActiveAlerts_RejectsOn401WithActionableMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := fetchActiveAlerts(context.Background(), &http.Client{}, server.URL, "stale-token")
	if err == nil {
		t.Fatal("expected an error on 401, got nil")
	}
	if !strings.Contains(err.Error(), "service account token") {
		t.Errorf("error = %q, want an actionable hint mentioning the service account token", err.Error())
	}
}
