package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
)

func TestCheckHealth_OkWhenDatabaseReachable(t *testing.T) {
	app := newTestDB(t)

	result, err := app.CheckHealth(context.Background(), &backend.CheckHealthRequest{})
	if err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
	if result.Status != backend.HealthStatusOk {
		t.Errorf("Status = %v, want %v, message: %s", result.Status, backend.HealthStatusOk, result.Message)
	}
}

// Security-audit finding M1: CheckHealth used to always report
// HealthStatusOk regardless of the database's actual state -- the HTTP
// /health route already correctly called PingDB, but the SDK's own
// CheckHealth (what Grafana itself surfaces in the plugin health UI) did
// not, so a broken database could sit behind an always-green health check.
func TestCheckHealth_ErrorWhenDatabaseUnreachable(t *testing.T) {
	app := newTestDB(t)
	if err := app.CloseDB(); err != nil {
		t.Fatalf("CloseDB failed: %v", err)
	}

	result, err := app.CheckHealth(context.Background(), &backend.CheckHealthRequest{})
	if err != nil {
		t.Fatalf("CheckHealth returned error: %v", err)
	}
	if result.Status != backend.HealthStatusError {
		t.Errorf("Status = %v, want %v", result.Status, backend.HealthStatusError)
	}
}

// Security-audit finding M6: handleHealth used fmt.Fprintf to hand-build
// the JSON error response -- a message containing a quote or backslash
// produced invalid JSON. json.NewEncoder always produces valid JSON
// regardless of the message content.
func TestHandleHealth_FailureResponseIsValidJSON(t *testing.T) {
	app := newTestDB(t)
	if err := app.CloseDB(); err != nil {
		t.Fatalf("CloseDB failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	app.handleHealth(w, req)

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["status"] != "error" {
		t.Errorf(`status = %q, want "error"`, body["status"])
	}
}
