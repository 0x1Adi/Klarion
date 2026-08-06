package verify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// cannedAnthropicResponse wraps a results JSON payload in the Messages API
// response envelope (a single text content block).
func cannedAnthropicResponse(t *testing.T, results batchResults) string {
	t.Helper()
	inner, err := json.Marshal(results)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": string(inner)},
		},
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestAnthropicVerifyParsingAndHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %q, want /v1/messages", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		gotHeaders = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)

		results := batchResults{Results: []batchResult{
			{Index: 0, Status: "secret", Confidence: 0.97, Reason: "live aws key"},
			{Index: 1, Status: "false_positive", Confidence: 0.9, Reason: "example placeholder"},
			// index 2 intentionally omitted -> defaults to uncertain.
		}}
		w.Header().Set("content-type", "application/json")
		io.WriteString(w, cannedAnthropicResponse(t, results))
	}))
	defer srv.Close()

	t.Setenv("KLARION_ANTHROPIC_KEY", "sk-test-123")
	v := newAnthropic(&config.AIConfig{
		Provider:    "anthropic",
		Model:       "claude-haiku-4-5",
		BaseURL:     srv.URL,
		APIKeyEnv:   "KLARION_ANTHROPIC_KEY",
		TimeoutSecs: 10,
	})

	batch := []Request{
		{Index: 0, RuleID: "aws-access-key-id", Secret: "AKIA...", Entropy: 0.9},
		{Index: 1, RuleID: "generic-high-entropy", Secret: "your-key", Entropy: 0.5},
		{Index: 2, RuleID: "generic-high-entropy", Secret: "abc", Entropy: 0.8},
	}
	verdicts, err := v.Verify(context.Background(), batch)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Header assertions.
	if got := gotHeaders.Get("x-api-key"); got != "sk-test-123" {
		t.Errorf("x-api-key = %q, want sk-test-123", got)
	}
	if got := gotHeaders.Get("anthropic-version"); got != anthropicVersion {
		t.Errorf("anthropic-version = %q, want %q", got, anthropicVersion)
	}
	if got := gotHeaders.Get("content-type"); !strings.Contains(got, "application/json") {
		t.Errorf("content-type = %q, want application/json", got)
	}

	// Body shape assertions.
	if gotBody["model"] != "claude-haiku-4-5" {
		t.Errorf("model = %v, want claude-haiku-4-5", gotBody["model"])
	}
	if _, ok := gotBody["output_config"]; !ok {
		t.Error("request missing output_config (structured outputs)")
	}
	if _, ok := gotBody["system"]; !ok {
		t.Error("request missing system prompt")
	}

	// Verdict mapping assertions.
	if len(verdicts) != 3 {
		t.Fatalf("got %d verdicts, want 3", len(verdicts))
	}
	if verdicts[0].Status != finding.VerdictSecret || verdicts[0].Confidence != 0.97 {
		t.Errorf("verdict[0] = %+v, want secret/0.97", verdicts[0])
	}
	if verdicts[0].Verifier != "anthropic:claude-haiku-4-5" {
		t.Errorf("verifier = %q, want anthropic:claude-haiku-4-5", verdicts[0].Verifier)
	}
	if verdicts[1].Status != finding.VerdictFalsePositive {
		t.Errorf("verdict[1] = %+v, want false_positive", verdicts[1])
	}
	// Missing index defaults to uncertain (security-safe).
	if verdicts[2].Status != finding.VerdictUncertain {
		t.Errorf("verdict[2] = %+v, want uncertain (defaulted)", verdicts[2])
	}
}

func TestAnthropicHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"type":"authentication_error","message":"invalid key"}}`)
	}))
	defer srv.Close()

	t.Setenv("KLARION_ANTHROPIC_KEY", "sk-bad")
	v := newAnthropic(&config.AIConfig{BaseURL: srv.URL, APIKeyEnv: "KLARION_ANTHROPIC_KEY", TimeoutSecs: 10})

	if _, err := v.Verify(context.Background(), []Request{{Index: 0, Secret: "x"}}); err == nil {
		t.Error("expected error on HTTP 401")
	}
}

func TestAnthropicMissingKey(t *testing.T) {
	t.Setenv("KLARION_ANTHROPIC_KEY", "")
	v := newAnthropic(&config.AIConfig{APIKeyEnv: "KLARION_ANTHROPIC_KEY"})
	if _, err := v.Verify(context.Background(), []Request{{Index: 0, Secret: "x"}}); err == nil {
		t.Error("expected error when API key is missing")
	}
}

func TestAnthropicFencedJSON(t *testing.T) {
	// Some responses wrap JSON in a ```json fence; parsing must still work.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fenced := "```json\n{\"results\":[{\"index\":0,\"status\":\"secret\",\"confidence\":0.8,\"reason\":\"x\"}]}\n```"
		env := map[string]any{"content": []map[string]any{{"type": "text", "text": fenced}}}
		out, _ := json.Marshal(env)
		w.Write(out)
	}))
	defer srv.Close()

	t.Setenv("KLARION_ANTHROPIC_KEY", "sk-test")
	v := newAnthropic(&config.AIConfig{BaseURL: srv.URL, APIKeyEnv: "KLARION_ANTHROPIC_KEY", TimeoutSecs: 10})
	verdicts, err := v.Verify(context.Background(), []Request{{Index: 0, Secret: "x"}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdicts[0].Status != finding.VerdictSecret {
		t.Errorf("verdict = %+v, want secret", verdicts[0])
	}
}

func TestAnthropicName(t *testing.T) {
	if got := newAnthropic(&config.AIConfig{}).Name(); got != "anthropic" {
		t.Errorf("Name = %q, want anthropic", got)
	}
}

func TestMapStatus(t *testing.T) {
	cases := map[string]finding.VerdictStatus{
		"secret":         finding.VerdictSecret,
		"false_positive": finding.VerdictFalsePositive,
		"uncertain":      finding.VerdictUncertain,
		"garbage":        finding.VerdictUncertain,
		"":               finding.VerdictUncertain,
	}
	for in, want := range cases {
		if got := mapStatus(in); got != want {
			t.Errorf("mapStatus(%q) = %q, want %q", in, got, want)
		}
	}
}
