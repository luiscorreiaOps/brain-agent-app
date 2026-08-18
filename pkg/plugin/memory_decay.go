package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"strings"

	"github.com/grafana/grafana-plugin-sdk-go/backend/log"
)

// memoryDecayHalfLifeDays controls how fast a fact's ranking weight decays
// since it was last matched by a search (or, if never matched again since
// creation, since it was created). Targets the roadmap's actual concern:
// without this, ranking was embedding-if-configured, else word-overlap,
// else pure recency, with no way for a fact nobody has needed in months
// (e.g. a stale IP/DNS entry that still text-matches perfectly) to lose
// ground to one that keeps getting confirmed relevant.
const memoryDecayHalfLifeDays = 14.0

// memoryDecayFloor is the minimum decay weight -- a fact's ranking is never
// reduced past this no matter how old, so decay only ever re-orders among
// matches, it never effectively hides the strongest match just because it's
// old.
const memoryDecayFloor = 0.25

// memoryDecayAgeDaysExpr is a SQL fragment computing "days since this row
// was last accessed, or created if never accessed again" -- callers append
// it to a SELECT and pass the resulting column straight to
// memoryDecayWeight. Age is computed here, in SQLite, rather than by
// parsing a timestamp string back out in Go: the driver in use
// (modernc.org/sqlite) does not return a single stable string
// representation for a DATETIME column's contents to a Go string scan
// target -- it varies depending on whether the value was written by a Go-
// formatted literal (e.g. expires_at) or by a SQL date function/default
// (e.g. datetime('now', ...), CURRENT_TIMESTAMP). Doing the subtraction in
// SQL sidesteps that entirely, since SQLite always understands its own
// storage regardless of which path wrote it.
const memoryDecayAgeDaysExpr = "(julianday('now') - julianday(COALESCE(last_accessed, created_at)))"

// memoryDecayWeight turns an age-in-days (as produced by
// memoryDecayAgeDaysExpr) into a 0..1 ranking multiplier: 1.0 for a fact
// accessed (or created) just now, decaying toward memoryDecayFloor as that
// reference point recedes into the past. A NULL or non-positive age (clock
// skew, or a row somehow missing both timestamps) returns 1.0 -- no decay --
// rather than guessing.
func memoryDecayWeight(ageDays sql.NullFloat64) float64 {
	if !ageDays.Valid || ageDays.Float64 <= 0 {
		return 1.0
	}
	weight := math.Pow(0.5, ageDays.Float64/memoryDecayHalfLifeDays)
	if weight < memoryDecayFloor {
		return memoryDecayFloor
	}
	return weight
}

// touchLastAccessed marks the given fact IDs as just matched by a search --
// their next decay computation starts from this moment instead of from
// created_at, so a fact that keeps getting matched never decays away, while
// one nobody has needed in a long time naturally sinks in ranking against
// equally-scored, recently-confirmed facts. Best-effort: a failure here only
// costs this one ranking signal for next time, never the search result
// already computed, so it's logged and swallowed rather than surfaced as an
// error to the caller.
func (a *App) touchLastAccessed(ctx context.Context, ids []int64) {
	if a.db == nil || len(ids) == 0 {
		return
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	query := fmt.Sprintf("UPDATE memory_store SET last_accessed = CURRENT_TIMESTAMP WHERE id IN (%s)", strings.Join(placeholders, ","))
	if _, err := a.db.ExecContext(ctx, query, args...); err != nil {
		log.DefaultLogger.Warn("failed to update last_accessed for matched facts", "error", err)
	}
}
