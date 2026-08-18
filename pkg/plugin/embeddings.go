package plugin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// embeddingEndpointURL/embeddingModel/embeddingAPIKey configure a real
// semantic-search backend for SearchMemory -- an OpenAI-compatible
// /embeddings endpoint (Ollama, OpenAI, or any compatible gateway). All
// three are optional and off by default (package-level, set once from
// NewApp/Settings, same convention as atRestEncryptionEnabled/
// piiDetectionEnabled): without them, SearchMemory behaves exactly as
// before this feature existed (the "TF-IDF-lite" lexical scoring in
// scoreFact). This plugin intentionally has no vector-store dependency --
// embeddings are stored as a JSON-encoded float array in memory_store and
// ranked with brute-force cosine similarity (embeddingSearchCandidateCap
// bounds the scan), which is the right trade-off at the fact counts this
// plugin is actually used at, without tensioning the "SQLite, zero extra
// services" design this plugin otherwise keeps.
// embeddingSearchCandidateCap bounds how many of a project's facts get a
// cosine-similarity comparison per search_memory call -- brute-force
// cosine over an unbounded fact count would make search latency scale
// linearly with how long a project has been in use. Facts beyond this cap
// (oldest-first, since the candidate query already orders by created_at
// DESC) are simply not considered for the embedding-ranked path; they're
// still reachable via the lexical fallback path.
const embeddingSearchCandidateCap = 2000

func (a *App) embeddingsConfigured() bool {
	return a.embeddingEndpointURL != "" && a.embeddingModel != ""
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Embedding []float64 `json:"embedding"`
	} `json:"data"`
}

// computeEmbedding calls the configured /embeddings endpoint for one piece
// of text. Returns an error whenever no embedding could be obtained --
// every call site treats that as "no embedding available right now" and
// falls back to the existing lexical search, never as a fatal error, since
// this whole feature is optional and must degrade gracefully when unset,
// unreachable, or slow.
func (a *App) computeEmbedding(ctx context.Context, text string) ([]float64, error) {
	if !a.embeddingsConfigured() {
		return nil, fmt.Errorf("no embedding endpoint configured")
	}
	body, err := json.Marshal(embeddingRequest{Model: a.embeddingModel, Input: text})
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(a.embeddingEndpointURL, "/") + "/embeddings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.embeddingAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.embeddingAPIKey)
	}

	// EmbeddingEndpointURL is admin-configured free text -- newSafeHTTPClient
	// blocks it from resolving to the cloud metadata range (security-audit
	// finding H3), the one destination with no legitimate reason to ever be
	// configured here.
	client := newSafeHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding endpoint returned status %d", resp.StatusCode)
	}

	var parsed embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Data) == 0 || len(parsed.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embedding response had no vector")
	}
	return parsed.Data[0].Embedding, nil
}

// cosineSimilarity returns the cosine similarity of two vectors, in
// [-1, 1]. Returns 0 (treated as "no match") if either vector is empty or
// their lengths differ -- a length mismatch means the embedding model
// changed since one of the two was computed, which is safer to treat as
// "not comparable" than to panic or produce a meaningless score.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// encodeEmbedding/decodeEmbedding round-trip a []float64 through the
// memory_store.embedding TEXT column as JSON -- SQLite has no native
// vector/array type.
func encodeEmbedding(v []float64) (string, error) {
	if len(v) == 0 {
		return "", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeEmbedding(s string) []float64 {
	if s == "" {
		return nil
	}
	var v []float64
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

// embeddingMinSimilarity is the minimum cosine similarity for a fact to
// count as a real semantic match -- below this, a fact is considered
// unrelated to the query rather than a weak match, mirroring the lexical
// path's "score > 0" cutoff. Deliberately conservative (real semantic
// matches from a decent embedding model typically score well above this)
// since a false "match" here is a worse failure mode than falling through
// to the lexical path for a query the embedding path genuinely can't help
// with.
const embeddingMinSimilarity = 0.3

type embeddingScoredFact struct {
	ID         int64
	Fact       string
	Similarity float64
	// Weighted is Similarity with memoryDecayWeight applied -- ranking
	// sorts by this, not raw Similarity, so a fact nobody has needed
	// recently loses ranking priority against an equally-similar one that
	// keeps getting matched. The embeddingMinSimilarity cutoff above still
	// applies to the raw Similarity, never to Weighted -- decay re-orders
	// among real matches, it never turns a non-match into one.
	Weighted float64
}

// searchViaEmbeddings ranks a project's approved, non-expired facts by
// cosine similarity against query's own embedding. ok is false whenever
// this path can't be used for this call -- the query itself couldn't be
// embedded (endpoint down), or no fact in the project has a stored
// embedding yet (e.g. every fact predates enabling this feature) -- so the
// caller always has a clear signal to fall through to the lexical paths
// instead of silently returning nothing.
func (a *App) searchViaEmbeddings(ctx context.Context, project, query string) ([]string, bool) {
	queryVec, err := a.computeEmbedding(ctx, query)
	if err != nil {
		return nil, false
	}

	rows, err := a.db.QueryContext(ctx,
		`SELECT id, fact, is_encrypted, embedding, `+memoryDecayAgeDaysExpr+` FROM memory_store
		 WHERE project = ? AND status = 'approved' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at DESC LIMIT ?`,
		project, embeddingSearchCandidateCap)
	if err != nil {
		return nil, false
	}
	defer func() { _ = rows.Close() }()

	var scored []embeddingScoredFact
	anyEmbedding := false
	for rows.Next() {
		var id int64
		var fact, embeddingStr string
		var isEncrypted bool
		var ageDays sql.NullFloat64
		if err := rows.Scan(&id, &fact, &isEncrypted, &embeddingStr, &ageDays); err != nil {
			continue
		}
		vec := decodeEmbedding(embeddingStr)
		if len(vec) == 0 {
			continue
		}
		anyEmbedding = true
		fact = a.decryptTrackingFailures(fact, isEncrypted)
		if sim := cosineSimilarity(queryVec, vec); sim >= embeddingMinSimilarity {
			weight := memoryDecayWeight(ageDays)
			scored = append(scored, embeddingScoredFact{ID: id, Fact: fact, Similarity: sim, Weighted: sim * weight})
		}
	}
	if !anyEmbedding {
		return nil, false
	}

	sort.Slice(scored, func(i, j int) bool { return scored[i].Weighted > scored[j].Weighted })

	results := make([]string, 0, len(scored))
	var matchedIDs []int64
	for i, sf := range scored {
		if i >= a.maintenanceMaxResults {
			break
		}
		results = append(results, sf.Fact)
		matchedIDs = append(matchedIDs, sf.ID)
	}
	a.touchLastAccessed(ctx, matchedIDs)
	return results, true
}
