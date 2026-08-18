package plugin

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// blockedIPRanges deliberately does NOT include the general private
// ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or loopback --
// GrafanaURL and EmbeddingEndpointURL both legitimately, commonly point at
// exactly those (Grafana reachable at localhost from its own plugin, a
// self-hosted embeddings model like Ollama on a Docker bridge IP such as
// 172.17.0.1). Blocking those would break the primary real deployment
// pattern, not just a hypothetical attack. What's actually blocked is the
// cloud metadata service range (169.254.0.0/16, which includes
// 169.254.169.254 -- AWS/GCP/Azure/DigitalOcean's well-known instance
// metadata IP): there is no legitimate reason either setting would ever
// need to resolve there, and reaching it can hand an attacker this
// instance's own cloud IAM credentials (security-audit findings H2/H3).
// Both settings are admin-configured (never derived from a per-request
// value a lower-privileged user controls), so this is defense-in-depth
// against a compromised config value (e.g. a bad provisioning pipeline),
// not a classic user-input SSRF.
var blockedIPRanges = mustParseCIDRs(
	"169.254.0.0/16", // link-local v4, includes cloud metadata endpoints
	"fe80::/10",      // link-local v6, includes cloud metadata endpoints
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", c, err))
		}
		nets = append(nets, n)
	}
	return nets
}

func isBlockedIP(ip net.IP) bool {
	for _, n := range blockedIPRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// newSafeHTTPClient returns an http.Client that refuses to connect to any
// address in blockedIPRanges. The check happens inside the dialer's
// Control hook, which fires with the address Go's own resolver already
// settled on for THIS specific connection attempt -- not a separate
// resolve-then-compare-then-connect step, which a DNS rebinding attack
// defeats (the hostname can resolve to a safe IP during the check and a
// blocked one moments later, when the real connection is dialed). Applied
// to any admin-configured external URL this plugin calls on its own
// initiative (AutoLearnAlerts' GrafanaURL, embeddings' EmbeddingEndpointURL).
func newSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("could not parse resolved IP %q", host)
			}
			if isBlockedIP(ip) {
				return fmt.Errorf("refusing to connect to %s: address is in a blocked private/link-local range", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
}
