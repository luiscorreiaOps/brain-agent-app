package plugin

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCosineSimilarity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a, b []float64
		want float64
	}{
		{"identical vectors", []float64{1, 0, 0}, []float64{1, 0, 0}, 1},
		{"orthogonal vectors", []float64{1, 0}, []float64{0, 1}, 0},
		{"opposite vectors", []float64{1, 0}, []float64{-1, 0}, -1},
		{"empty a", nil, []float64{1, 0}, 0},
		{"mismatched lengths", []float64{1, 0}, []float64{1, 0, 0}, 0},
		{"zero vector", []float64{0, 0}, []float64{1, 0}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := cosineSimilarity(tc.a, tc.b)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("cosineSimilarity(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestEncodeDecodeEmbedding_RoundTrips(t *testing.T) {
	t.Parallel()

	original := []float64{0.1, -0.2, 0.3, 1.5}
	encoded, err := encodeEmbedding(original)
	if err != nil {
		t.Fatalf("encodeEmbedding failed: %v", err)
	}
	decoded := decodeEmbedding(encoded)
	if len(decoded) != len(original) {
		t.Fatalf("decoded length = %d, want %d", len(decoded), len(original))
	}
	for i := range original {
		if math.Abs(decoded[i]-original[i]) > 1e-9 {
			t.Errorf("decoded[%d] = %v, want %v", i, decoded[i], original[i])
		}
	}
}

func TestEncodeEmbedding_EmptyVectorRoundTripsToNil(t *testing.T) {
	t.Parallel()

	encoded, err := encodeEmbedding(nil)
	if err != nil {
		t.Fatalf("encodeEmbedding(nil) failed: %v", err)
	}
	if encoded != "" {
		t.Errorf("encodeEmbedding(nil) = %q, want empty string", encoded)
	}
	if got := decodeEmbedding(""); got != nil {
		t.Errorf("decodeEmbedding(\"\") = %v, want nil", got)
	}
}

func TestDecodeEmbedding_MalformedJSONReturnsNil(t *testing.T) {
	t.Parallel()

	if got := decodeEmbedding("not json"); got != nil {
		t.Errorf("decodeEmbedding(malformed) = %v, want nil", got)
	}
}

// fakeVector deterministically maps a piece of text to a small vector so
// tests can assert real similarity relationships without a real embedding
// model -- same-topic strings share more non-zero dimensions than
// unrelated ones.
func fakeVector(text string) []float64 {
	switch text {
	case "vault secrets manager outage", "the vault pod restarted after an oom kill":
		return []float64{1, 1, 0, 0}
	case "checkout latency spike":
		return []float64{0, 0, 1, 1}
	default:
		return []float64{0.5, 0.5, 0.5, 0.5}
	}
}

func newFakeEmbeddingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req embeddingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(embeddingResponse{
			Data: []struct {
				Embedding []float64 `json:"embedding"`
			}{{Embedding: fakeVector(req.Input)}},
		})
	}))
}

func TestComputeEmbedding_NotConfiguredReturnsError(t *testing.T) {
	app := &App{}
	if _, err := app.computeEmbedding(context.Background(), "hello"); err == nil {
		t.Error("expected an error when no embedding endpoint is configured")
	}
}

func TestComputeEmbedding_RealCallAgainstMockServer(t *testing.T) {
	server := newFakeEmbeddingServer(t)
	defer server.Close()

	app := &App{embeddingEndpointURL: server.URL, embeddingModel: "test-embed-model"}

	vec, err := app.computeEmbedding(context.Background(), "checkout latency spike")
	if err != nil {
		t.Fatalf("computeEmbedding failed: %v", err)
	}
	want := []float64{0, 0, 1, 1}
	if len(vec) != len(want) {
		t.Fatalf("vec = %v, want %v", vec, want)
	}
	for i := range want {
		if vec[i] != want[i] {
			t.Errorf("vec[%d] = %v, want %v", i, vec[i], want[i])
		}
	}
}

func TestSearchViaEmbeddings_RanksBySemanticSimilarityNotSharedWords(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	server := newFakeEmbeddingServer(t)
	defer server.Close()
	app.embeddingEndpointURL, app.embeddingModel = server.URL, "test-embed-model"

	if err := app.StoreMemory(ctx, "embed-project", "the vault pod restarted after an oom kill"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}
	if err := app.StoreMemory(ctx, "embed-project", "checkout latency spike"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	results, ok := app.searchViaEmbeddings(ctx, "embed-project", "vault secrets manager outage")
	if !ok {
		t.Fatal("searchViaEmbeddings returned ok=false, want true (embeddings configured and stored)")
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly 1 semantic match", results)
	}
	if results[0] != "the vault pod restarted after an oom kill" {
		t.Errorf("results[0] = %q, want the vault-related fact despite sharing no words with the query", results[0])
	}
}

func TestSearchViaEmbeddings_NoStoredEmbeddingsReturnsNotOK(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	// Store a fact with embeddings OFF, then flip embeddings on only for
	// the search call -- simulates facts written before this feature was
	// configured.
	if err := app.StoreMemory(ctx, "no-embed-project", "some fact written before embeddings were enabled"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	server := newFakeEmbeddingServer(t)
	defer server.Close()
	app.embeddingEndpointURL, app.embeddingModel = server.URL, "test-embed-model"

	_, ok := app.searchViaEmbeddings(ctx, "no-embed-project", "anything")
	if ok {
		t.Error("expected ok=false when no fact in the project has a stored embedding")
	}
}

func TestSearchMemory_FallsBackToLexicalWhenEmbeddingsNotConfigured(t *testing.T) {
	app := newTestDB(t)
	ctx := context.Background()

	if err := app.StoreMemory(ctx, "fallback-project", "the vault pod restarted after an oom kill"); err != nil {
		t.Fatalf("StoreMemory failed: %v", err)
	}

	results, err := app.SearchMemory(ctx, "fallback-project", "vault pod restarted", true)
	if err != nil {
		t.Fatalf("SearchMemory failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want exactly 1 lexical match", results)
	}
}
