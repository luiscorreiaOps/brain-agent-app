package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// autoLearnPollInterval is how often the poller checks Grafana's alerting
// API for alerts that have stopped firing since the last check. Alerts
// don't need sub-minute reaction time here -- this is memory for an
// assistant to reference later, not paging.
const autoLearnPollInterval = 5 * time.Minute

// alertsAPIPath is the Alertmanager-compatible endpoint every Grafana
// version since the Grafana-managed alerting rewrite exposes for the
// currently active/firing alert set (not history) -- stable across
// versions, unlike the alerting state-history API.
const alertsAPIPath = "/api/alertmanager/grafana/api/v2/alerts?active=true&silenced=false&inhibited=false&unprocessed=false"

// gettableAlert is the subset of Alertmanager v2's GettableAlert this
// plugin needs -- labels/annotations to build a fact, fingerprint to track
// identity across polls, and StartsAt/EndsAt/GeneratorURL to enrich that
// fact with a real resolution time and a link back to the firing
// dashboard/panel, when Grafana provides one.
type gettableAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	Fingerprint  string            `json:"fingerprint"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Status       struct {
		State string `json:"state"`
	} `json:"status"`
}

// fetchActiveAlerts calls Grafana's own Alertmanager-compatible API and
// returns the currently firing alerts keyed by fingerprint.
func fetchActiveAlerts(ctx context.Context, client *http.Client, grafanaURL, token string) (map[string]gettableAlert, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(grafanaURL, "/")+alertsAPIPath, nil)
	if err != nil {
		return nil, fmt.Errorf("create alerts request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute alerts request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("grafana rejected this plugin's service account token (status %d) fetching alerts -- grafanaToken is likely invalid, expired, or lacks alerting read permission", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alerts API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, fmt.Errorf("read alerts response: %w", err)
	}

	var alerts []gettableAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("parse alerts response: %w", err)
	}

	byFingerprint := make(map[string]gettableAlert, len(alerts))
	for _, a := range alerts {
		if a.Status.State != "" && a.Status.State != "active" {
			continue
		}
		byFingerprint[a.Fingerprint] = a
	}
	return byFingerprint, nil
}

// alertProject picks which brain-agent project a resolved alert's fact
// should be stored under -- the same label names this repo's dashboards
// already use for scoping (see persona.go equivalents in the sibling
// plugins). Falls back to "default" so nothing is ever dropped for lack of
// a label.
func alertProject(labels map[string]string) string {
	for _, key := range []string{"namespace", "project", "job"} {
		if v := strings.TrimSpace(labels[key]); v != "" {
			return v
		}
	}
	return "default"
}

// alertLabelSummary formats a compact "key=value key=value" string from the
// labels most useful for later correlation -- service/namespace/severity are
// the ones this plugin's own project-scoping and structured-metadata
// already care about (see alertProject, MemoryMetadata), so surfacing them
// in the fact text itself keeps the human-readable fact self-contained even
// without the metadata columns.
func alertLabelSummary(labels map[string]string) string {
	var parts []string
	for _, key := range []string{"namespace", "service", "job", "severity"} {
		if v := strings.TrimSpace(labels[key]); v != "" {
			parts = append(parts, fmt.Sprintf("%s=%s", key, v))
		}
	}
	return strings.Join(parts, " ")
}

// resolvedAlertFact turns one alert that just stopped firing into a short,
// runbook-style fact worth remembering -- labels, a runbook link, and a
// dashboard/panel link (when Grafana provided one) are appended when
// present, and the real resolution time (EndsAt) is used instead of
// "now" whenever the alert payload actually has it.
func resolvedAlertFact(a gettableAlert) string {
	name := a.Labels["alertname"]
	if name == "" {
		name = "unknown alert"
	}
	summary := a.Annotations["summary"]
	if summary == "" {
		summary = a.Annotations["description"]
	}

	resolvedAt := time.Now().UTC()
	if !a.EndsAt.IsZero() {
		resolvedAt = a.EndsAt.UTC()
	}

	fact := fmt.Sprintf("Alert %q resolved at %s", name, resolvedAt.Format(time.RFC3339))
	if summary != "" {
		fact += ": " + summary
	} else {
		fact += "."
	}

	if labelSummary := alertLabelSummary(a.Labels); labelSummary != "" {
		fact += " [" + labelSummary + "]"
	}
	if runbook := strings.TrimSpace(a.Annotations["runbook_url"]); runbook != "" {
		fact += " Runbook: " + runbook
	}
	if link := alertDashboardLink(a); link != "" {
		fact += " Dashboard: " + link
	}
	return fact
}

// alertDashboardLink returns a dashboard/panel URL for the alert, if Grafana
// provided one -- preferring the annotations Grafana itself injects
// (__dashboardUid__/__panelId__) over the raw GeneratorURL, since the latter
// points at the alert rule editor, not the dashboard the alert was defined
// on.
func alertDashboardLink(a gettableAlert) string {
	if uid := strings.TrimSpace(a.Annotations["__dashboardUid__"]); uid != "" {
		link := "/d/" + uid
		if panelID := strings.TrimSpace(a.Annotations["__panelId__"]); panelID != "" {
			link += "?viewPanel=" + panelID
		}
		return link
	}
	return strings.TrimSpace(a.GeneratorURL)
}

// autoLearnStatusMu/autoLearnLastPollAt/autoLearnLastError (App fields, see
// app.go) back brain_diagnostics' "auto-learning" section for real --
// previously there was no way to tell whether the poller was even running,
// let alone whether its last poll succeeded.

func (a *App) recordAutoLearnPoll(err error) {
	a.autoLearnStatusMu.Lock()
	defer a.autoLearnStatusMu.Unlock()
	a.autoLearnEverStarted = true
	a.autoLearnLastPollAt = time.Now()
	if err != nil {
		a.autoLearnLastError = err.Error()
	} else {
		a.autoLearnLastError = ""
	}
}

// autoLearnStatus reports the poller's real state for brain_diagnostics.
func (a *App) autoLearnStatus() (started bool, lastPollAt time.Time, lastError string) {
	a.autoLearnStatusMu.Lock()
	defer a.autoLearnStatusMu.Unlock()
	return a.autoLearnEverStarted, a.autoLearnLastPollAt, a.autoLearnLastError
}

// resetAutoLearnStatus clears this App's poller state -- test-only, so a
// test that calls pollOnce directly (without going through the real ticker
// loop) doesn't leak "auto-learn has run" into a later assertion against
// the same *App.
func (a *App) resetAutoLearnStatus() {
	a.autoLearnStatusMu.Lock()
	defer a.autoLearnStatusMu.Unlock()
	a.autoLearnEverStarted = false
	a.autoLearnLastPollAt = time.Time{}
	a.autoLearnLastError = ""
}

// pollOnce fetches the current firing set and diffs it against
// previouslyFiring -- any fingerprint that was firing before and isn't
// anymore is treated as resolved and stored as a memory. Returns the new
// firing set to carry into the next poll.
func (a *App) pollOnce(ctx context.Context, client *http.Client, grafanaURL, token string, previouslyFiring map[string]gettableAlert) map[string]gettableAlert {
	current, err := fetchActiveAlerts(ctx, client, grafanaURL, token)
	a.recordAutoLearnPoll(err)
	if err != nil {
		a.logger.Warn("auto-learn: failed to fetch active alerts, skipping this round", "error", err)
		return previouslyFiring
	}

	for fingerprint, alert := range previouslyFiring {
		if _, stillFiring := current[fingerprint]; stillFiring {
			continue
		}
		fact := resolvedAlertFact(alert)
		meta := &MemoryMetadata{
			Type:      "incident",
			Source:    "auto-learn-alerts",
			Service:   alert.Labels["service"],
			Namespace: alert.Labels["namespace"],
		}
		if err := a.StoreMemoryWithMetadata(ctx, alertProject(alert.Labels), fact, meta); err != nil {
			a.logger.Error("auto-learn: failed to store resolved-alert memory", "error", err, "alert", alert.Labels["alertname"])
			continue
		}
		a.logger.Info("auto-learn: stored memory for resolved alert", "alert", alert.Labels["alertname"], "project", alertProject(alert.Labels))
	}

	return current
}

// startAutoLearnAlerts runs pollOnce on a ticker until ctx is cancelled
// (Dispose). The very first poll only seeds the firing set -- nothing can
// be reported "resolved" before we've seen it firing at least once, so no
// facts are stored until the second tick at the earliest.
func (a *App) startAutoLearnAlerts(ctx context.Context, grafanaURL, token string) {
	// GrafanaURL is admin-configured free text -- newSafeHTTPClient blocks
	// it from resolving to a private/link-local address (security-audit
	// finding H2), e.g. a cloud metadata endpoint or an internal service
	// this plugin has no business reaching.
	client := newSafeHTTPClient(30 * time.Second)
	go func() {
		firing := a.pollOnce(ctx, client, grafanaURL, token, map[string]gettableAlert{})
		ticker := time.NewTicker(autoLearnPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				firing = a.pollOnce(ctx, client, grafanaURL, token, firing)
			}
		}
	}()
}
