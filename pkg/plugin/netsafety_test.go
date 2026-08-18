package plugin

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IP literal in test: %q", s)
	}
	return ip
}

// Security-audit findings H2/H3: the one destination worth categorically
// blocking is the cloud metadata range -- no legitimate GrafanaURL or
// EmbeddingEndpointURL configuration would ever need it, and reaching it
// can hand an attacker this instance's own cloud IAM credentials.
func TestNewSafeHTTPClient_BlocksCloudMetadataRange(t *testing.T) {
	t.Parallel()

	client := newSafeHTTPClient(2 * time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected an error connecting to the cloud metadata range, got nil")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error = %v, want it to mention the connection was blocked", err)
	}
}

// The whole point of scoping the block to just the metadata range: real,
// common configurations (Grafana at localhost, a self-hosted embeddings
// model on a Docker bridge IP) must keep working.
func TestNewSafeHTTPClient_AllowsPrivateAndLoopbackAddresses(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newSafeHTTPClient(2 * time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to a normal loopback test server should succeed, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestIsBlockedIP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ip      string
		blocked bool
	}{
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		{"127.0.0.1", false},
		{"10.0.0.5", false},
		{"172.17.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			ip := mustParseIP(t, tc.ip)
			if got := isBlockedIP(ip); got != tc.blocked {
				t.Errorf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}
