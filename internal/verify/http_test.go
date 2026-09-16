package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// zeroBackoff removes the retry delay for the duration of a test.
func zeroBackoff(t *testing.T) {
	t.Helper()
	prev := httpBackoff
	httpBackoff = 0
	t.Cleanup(func() { httpBackoff = prev })
}

func TestPostJSONRetriesTransientFailures(t *testing.T) {
	zeroBackoff(t)

	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, 529} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if atomic.AddInt32(&calls, 1) == 1 {
					w.WriteHeader(status)
					return
				}
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer srv.Close()

			resp, err := postJSON(context.Background(), srv.Client(), "test", srv.URL, []byte(`{}`), http.Header{})
			if err != nil {
				t.Fatalf("postJSON: %v", err)
			}
			if resp.status != http.StatusOK {
				t.Errorf("status = %d, want 200 after retry", resp.status)
			}
			if got := atomic.LoadInt32(&calls); got != 2 {
				t.Errorf("attempts = %d, want 2", got)
			}
		})
	}
}

func TestPostJSONDoesNotRetryClientErrors(t *testing.T) {
	zeroBackoff(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	resp, err := postJSON(context.Background(), srv.Client(), "test", srv.URL, []byte(`{}`), http.Header{})
	if err != nil {
		t.Fatalf("postJSON: %v", err)
	}
	if resp.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 surfaced to the caller", resp.status)
	}
	// A bad key fails identically every time; retrying only wastes the user's time.
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on 401)", got)
	}
}

func TestPostJSONGivesUpAfterMaxAttempts(t *testing.T) {
	zeroBackoff(t)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	if _, err := postJSON(context.Background(), srv.Client(), "test", srv.URL, []byte(`{}`), http.Header{}); err == nil {
		t.Fatal("want an error when every attempt fails")
	}
	if got := atomic.LoadInt32(&calls); got != httpAttempts {
		t.Errorf("attempts = %d, want %d", got, httpAttempts)
	}
}

// Every attempt must carry the full body; a consumed reader cannot be replayed.
func TestPostJSONResendsBodyOnRetry(t *testing.T) {
	zeroBackoff(t)

	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		bodies = append(bodies, string(buf))
		if len(bodies) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	payload := `{"hello":"world"}`
	if _, err := postJSON(context.Background(), srv.Client(), "test", srv.URL, []byte(payload), http.Header{}); err != nil {
		t.Fatal(err)
	}
	for i, b := range bodies {
		if b != payload {
			t.Errorf("attempt %d body = %q, want %q", i+1, b, payload)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Errorf("seconds form = %v, want 5s", got)
	}
	if got := parseRetryAfter("garbage"); got != 0 {
		t.Errorf("unparseable = %v, want 0", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("absent = %v, want 0", got)
	}
	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 {
		t.Errorf("http-date form = %v, want a positive delay", got)
	}
}

func TestBackoffRespectsRetryAfterAndCeiling(t *testing.T) {
	prev := httpBackoff
	httpBackoff = time.Second
	defer func() { httpBackoff = prev }()

	if got := backoffFor(2, 0); got != time.Second {
		t.Errorf("attempt 2 = %v, want 1s", got)
	}
	if got := backoffFor(3, 0); got != 2*time.Second {
		t.Errorf("attempt 3 = %v, want 2s", got)
	}
	if got := backoffFor(2, 10*time.Second); got != 10*time.Second {
		t.Errorf("server hint = %v, want 10s", got)
	}
	if got := backoffFor(2, time.Hour); got != maxRetryBackoff {
		t.Errorf("pathological hint = %v, want it clamped to %v", got, maxRetryBackoff)
	}
}

// The Anthropic request must stay within what the Messages API accepts:
// structured outputs reject numerical constraints, and the output budget has to
// grow with the batch or a large batch truncates mid-JSON.
func TestAnthropicRequestShape(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")

	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"results\":[]}"}]}`))
	}))
	defer srv.Close()

	v := newAnthropic(&config.AIConfig{Provider: "anthropic", BaseURL: srv.URL})
	batch := make([]Request, 20)
	for i := range batch {
		batch[i] = Request{RuleID: "r", Secret: "candidate"}
	}
	if _, err := v.Verify(context.Background(), batch); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	schema := body["output_config"].(map[string]any)["format"].(map[string]any)["schema"]
	props := schema.(map[string]any)["properties"].(map[string]any)
	item := props["results"].(map[string]any)["items"].(map[string]any)
	confidence := item["properties"].(map[string]any)["confidence"].(map[string]any)
	for _, banned := range []string{"minimum", "maximum", "multipleOf"} {
		if _, ok := confidence[banned]; ok {
			t.Errorf("schema sends %q, which structured outputs reject", banned)
		}
	}

	if got := body["max_tokens"].(float64); got <= 1024 {
		t.Errorf("max_tokens = %v for a batch of 20; want it scaled to the batch", got)
	}
}

// Out-of-range confidence is clamped on the way in, which is what lets the
// schema drop its numeric bounds.
func TestClampConfidence(t *testing.T) {
	for _, tc := range []struct{ in, want float64 }{
		{-1, 0}, {0, 0}, {0.5, 0.5}, {1, 1}, {7, 1},
	} {
		if got := clampConfidence(tc.in); got != tc.want {
			t.Errorf("clampConfidence(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// Apply fans batches out across workers; every finding must still receive the
// verdict for its own candidate.
func TestApplyParallelBatchesKeepVerdictsAligned(t *testing.T) {
	var concurrent, peak int32
	v := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			n := atomic.AddInt32(&concurrent, 1)
			for {
				old := atomic.LoadInt32(&peak)
				if n <= old || atomic.CompareAndSwapInt32(&peak, old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			atomic.AddInt32(&concurrent, -1)
			return finding.Verdict{Status: finding.VerdictSecret, Reason: r.Secret}
		},
	}

	findings := make([]finding.Finding, 40)
	for i := range findings {
		findings[i] = finding.Finding{RuleID: "r", Secret: string(rune('a' + i%26))}
		findings[i].Secret += string(rune('0' + i/26))
	}
	cfg := &config.AIConfig{MaxBatch: 2, MaxConcurrency: 8, SendSecret: true}

	if err := Apply(context.Background(), v, cfg, findings); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i := range findings {
		if findings[i].Verdict.Reason != findings[i].Secret {
			t.Fatalf("finding %d got the verdict for %q, want %q",
				i, findings[i].Verdict.Reason, findings[i].Secret)
		}
	}
	if atomic.LoadInt32(&peak) < 2 {
		t.Errorf("peak concurrency = %d; batches did not run in parallel", peak)
	}
}

// TestParseRetryAfterFractional guards the fix for a rate-limit failure seen
// against Groq: the header value was "20.3775", strconv.Atoi rejected it, the
// hint was dropped, and the scan retried after 1s and 2s against a window with
// 20 seconds left -- so every attempt was refused and the batch died.
func TestParseRetryAfterFractional(t *testing.T) {
	cases := map[string]time.Duration{
		"":        0,
		"20":      20 * time.Second,
		"20.3775": 20*time.Second + 377500*time.Microsecond,
		"0.5":     500 * time.Millisecond,
		"0":       0,
		"-3":      0,
		"soon":    0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestRetryAfterFromBody covers providers that state the delay in the error
// payload instead of the header.
func TestRetryAfterFromBody(t *testing.T) {
	groq := []byte(`{"error":{"message":"Rate limit reached for model ` +
		"`openai/gpt-oss-20b`" +
		` on tokens per minute (TPM): Limit 8000, Used 7945, Requested 2772. Please try again in 20.3775s.","code":"rate_limit_exceeded"}}`)
	if got := retryAfterFromBody(groq); got < 20*time.Second || got > 21*time.Second {
		t.Errorf("retryAfterFromBody(groq) = %v, want ~20.38s", got)
	}
	if got := retryAfterFromBody([]byte("please try again in 250ms")); got != 250*time.Millisecond {
		t.Errorf("ms form = %v, want 250ms", got)
	}
	if got := retryAfterFromBody([]byte("something else entirely")); got != 0 {
		t.Errorf("no match = %v, want 0", got)
	}
}

// TestBackoffHonoursServerHint: our own backoff must never shorten a longer
// server-provided wait, and the ceiling must still bound a pathological value.
func TestBackoffHonoursServerHint(t *testing.T) {
	if got := backoffFor(2, 20*time.Second); got != 20*time.Second {
		t.Errorf("backoffFor(2, 20s) = %v, want 20s", got)
	}
	if got := backoffFor(2, 0); got != httpBackoff {
		t.Errorf("backoffFor(2, 0) = %v, want %v", got, httpBackoff)
	}
	if got := backoffFor(2, time.Hour); got != maxRetryBackoff {
		t.Errorf("backoffFor(2, 1h) = %v, want the %v ceiling", got, maxRetryBackoff)
	}
}
