package plugin

import (
	"sync"
	"time"
)

// perUserRateLimiter is a plain sliding-window-per-minute counter -- no new
// dependency needed (golang.org/x/time/rate, used by the sibling plugins
// for the same purpose, isn't in this module's go.mod) for what only needs
// to gate a handful of MCP tool calls per user per minute. Backs
// BrainConfig.tsx's "Flood Protection (Queries/Min)" field, previously
// typed into the form and never read anywhere in this package.
type perUserRateLimiter struct {
	mu         sync.Mutex
	windows    map[string]*limiterWindow
	sweepCalls int
}

// limiterWindow tracks one user's recent call timestamps plus when they were
// last active, so idle entries can be evicted (see sweep) -- without this,
// windows grows one entry per distinct user for the life of the process
// with no upper bound, same class of issue as agent-ai-app's limiters map.
type limiterWindow struct {
	times    []time.Time
	lastUsed time.Time
}

// windowIdleEvictAfter/sweepEvery bound how long an idle user's window
// sticks around and how often the sweep runs (as a fraction of allow calls,
// so this never needs its own goroutine/ticker).
const (
	windowIdleEvictAfter = 30 * time.Minute
	sweepEvery           = 500
)

func newPerUserRateLimiter() *perUserRateLimiter {
	return &perUserRateLimiter{windows: make(map[string]*limiterWindow)}
}

// defaultFloodLimitPerMinute is used whenever the admin-configured limit is
// unset/non-positive. Security-audit finding: floodLimitPerMinute defaulting
// to true-unlimited meant a Viewer (before today's separate MCP RBAC fix) or
// any misbehaving caller could hammer store_memory/delete_memory at an
// unbounded rate. An admin who genuinely wants a much higher ceiling can set
// an explicit large value; 0/unset now means "use this safe default", not
// "no limit at all".
const defaultFloodLimitPerMinute = 60

// allow reports whether user may make one more call right now, given limit
// calls per rolling minute (defaultFloodLimitPerMinute when limit <= 0).
func (r *perUserRateLimiter) allow(user string, limit int) bool {
	if limit <= 0 {
		limit = defaultFloodLimitPerMinute
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.sweepIdleLocked(now)

	w, ok := r.windows[user]
	if !ok {
		w = &limiterWindow{}
		r.windows[user] = w
	}
	w.lastUsed = now

	cutoff := now.Add(-time.Minute)
	kept := w.times[:0]
	for _, t := range w.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		w.times = kept
		return false
	}
	w.times = append(kept, now)
	return true
}

// sweepIdleLocked removes windows unused for windowIdleEvictAfter, running
// roughly every sweepEvery calls rather than on every call. Caller must hold r.mu.
func (r *perUserRateLimiter) sweepIdleLocked(now time.Time) {
	r.sweepCalls++
	if r.sweepCalls%sweepEvery != 0 {
		return
	}
	cutoff := now.Add(-windowIdleEvictAfter)
	for user, w := range r.windows {
		if w.lastUsed.Before(cutoff) {
			delete(r.windows, user)
		}
	}
}
