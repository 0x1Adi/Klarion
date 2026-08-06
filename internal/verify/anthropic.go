package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// defaultAnthropicBaseURL is the public Messages API host. Overridable via
// ai.base_url for proxies / gateways.
const defaultAnthropicBaseURL = "https://api.anthropic.com"

// anthropicVersion is the required API version header. Pinned intentionally:
// the request/response shape we depend on is stable for this version.
const anthropicVersion = "2023-06-01"

// defaultAnthropicModel is a fast, cheap classifier — good enough for a
// binary-ish "is this a real leaked secret" judgement.
const defaultAnthropicModel = "claude-haiku-4-5"

// systemPrompt is shared by every LLM provider so their behavior is identical.
// It is deliberately security-biased: for a secret scanner, a missed real
// secret is far worse than an extra false alarm, so the model must err toward
// "secret" whenever it is unsure. Only clearly documented examples / obvious
// fakes are false positives.
const systemPrompt = `You are a security secret-verification assistant embedded in a code-secret scanner.
For each candidate you are given (a regex/entropy match plus its surrounding code context), decide whether it is:
  - "secret": a REAL, live, leaked credential (API key, token, private key, password, connection string, ...).
  - "false_positive": clearly NOT a real secret — a placeholder or example (e.g. "your-api-key-here", "xxxx", "changeme"),
     a value inside a test fixture / documentation / sample, or a non-secret identifier such as a UUID, a git commit SHA,
     a public key/id, a hash, or a well-known constant.
  - "uncertain": you genuinely cannot tell.

CRITICAL BIAS: This is a security tool. A leaked secret that slips through is far more costly than a false alarm.
When in doubt, choose "secret", NOT "uncertain" or "false_positive". Only choose "false_positive" when the value is
clearly a documented example, an obvious placeholder, or provably a non-secret identifier.

Respond with a single JSON object of the form:
{"results":[{"index":<int>,"status":"secret|false_positive|uncertain","confidence":<0..1>,"reason":"<short>"}]}
Include exactly one result object per candidate, echoing back its "index". "confidence" is your certainty in the chosen
status. Keep "reason" to one short sentence. Output JSON only — no markdown, no prose.`

// batchResults is the structured output contract both providers must satisfy.
type batchResults struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Index      int     `json:"index"`
	Status     string  `json:"status"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// resultSchema is the JSON Schema advertised to providers that support
// structured outputs (Anthropic's output_config). Keeping additionalProperties
// false and marking fields required forces well-formed, parseable responses.
//
// Numeric bounds are deliberately absent from "confidence". Anthropic's
// structured outputs do not accept numerical constraints (minimum/maximum/
// multipleOf) — the official SDKs strip them before sending and validate
// client-side, and we talk to the API over plain net/http, so sending them
// would risk the schema being rejected and every batch failing. clampConfidence
// enforces the 0..1 range on the way back instead.
func resultSchema() map[string]any {
	item := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"index", "status", "confidence", "reason"},
		"properties": map[string]any{
			"index":      map[string]any{"type": "integer"},
			"status":     map[string]any{"type": "string", "enum": []string{"secret", "false_positive", "uncertain"}},
			"confidence": map[string]any{"type": "number"},
			"reason":     map[string]any{"type": "string"},
		},
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"results"},
		"properties": map[string]any{
			"results": map[string]any{"type": "array", "items": item},
		},
	}
}

// maxTokensFor sizes the output budget to the batch. Every candidate costs one
// small result object (index, status, confidence, one-sentence reason); a fixed
// budget that fits a batch of 2 truncates a batch of 20 mid-JSON, and truncated
// JSON fails to parse and costs the whole batch its verdicts.
func maxTokensFor(batchSize int) int {
	const (
		perCandidate = 128
		floor        = 1024
		ceiling      = 8192
	)
	n := batchSize * perCandidate
	switch {
	case n < floor:
		return floor
	case n > ceiling:
		return ceiling
	default:
		return n
	}
}

// buildUserPrompt renders the batch as compact JSON. We hand the model the same
// Request fields the rest of Klarion uses (rule id, entropy, context) so it has
// every signal we do; JSON keeps candidate boundaries unambiguous.
//
// Indices are rewritten positionally (0..len-1) regardless of what the caller
// put in Request.Index: mapResults assigns the echoed index as a position in
// this batch, so the two must agree even when a wrapper (e.g. the cache)
// hands us a deduplicated subset with sparse original indices.
func buildUserPrompt(batch []Request) string {
	prompt := make([]Request, len(batch))
	for i, r := range batch {
		r.Index = i
		prompt[i] = r
	}
	// json.Marshal never fails for these plain structs.
	// #nosec G117 -- the candidate secret is the payload: classifying it is
	// the point of the request, and it goes only to the configured provider.
	body, _ := json.Marshal(prompt)
	var b strings.Builder
	b.WriteString("Classify each of the following ")
	fmt.Fprintf(&b, "%d", len(batch))
	b.WriteString(" candidate secret(s). Candidates (JSON array):\n")
	b.Write(body)
	return b.String()
}

// mapStatus normalizes a model-provided status string to a VerdictStatus,
// defaulting unknown/empty values to VerdictUncertain (never silently "safe").
func mapStatus(s string) finding.VerdictStatus {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "secret":
		return finding.VerdictSecret
	case "false_positive", "false-positive", "falsepositive":
		return finding.VerdictFalsePositive
	case "uncertain":
		return finding.VerdictUncertain
	default:
		return finding.VerdictUncertain
	}
}

// noVerdictReason marks a verdict the model failed to return; consumers can
// use it to distinguish a real judgement from the safe default (the claude-cli
// provider re-queries such candidates).
const noVerdictReason = "model returned no verdict for this candidate"

// mapResults projects the model's results back onto the request order. Every
// request gets exactly one verdict; any index the model failed to return
// defaults to VerdictUncertain (a security-safe default — treated as a secret
// downstream).
func mapResults(batch []Request, br batchResults, verifierName string) []finding.Verdict {
	verdicts := make([]finding.Verdict, len(batch))
	seen := make([]bool, len(batch))
	for _, r := range br.Results {
		if r.Index < 0 || r.Index >= len(batch) || seen[r.Index] {
			continue
		}
		seen[r.Index] = true
		verdicts[r.Index] = finding.Verdict{
			Status:     mapStatus(r.Status),
			Confidence: clampConfidence(r.Confidence),
			Reason:     r.Reason,
			Verifier:   verifierName,
		}
	}
	for i := range verdicts {
		if !seen[i] {
			verdicts[i] = finding.Verdict{
				Status:   finding.VerdictUncertain,
				Reason:   noVerdictReason,
				Verifier: verifierName,
			}
		}
	}
	return verdicts
}

func clampConfidence(c float64) float64 {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	default:
		return c
	}
}

// anthropicVerifier adjudicates candidates via the Anthropic Messages API using
// raw net/http (no SDK dependency, to keep the binary lean and dependency-free).
type anthropicVerifier struct {
	model   string
	baseURL string
	apiKey  string
	timeout time.Duration
	client  *http.Client
}

// newAnthropic builds a verifier from config. The API key is resolved through
// keyEnvName so the provider can only ever read its own env var. An empty key
// is allowed here; Build decides whether that is fatal based on Mode.
func newAnthropic(cfg *config.AIConfig) *anthropicVerifier {
	model := cfg.Model
	if model == "" {
		model = defaultAnthropicModel
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = defaultAnthropicBaseURL
	}
	to := time.Duration(cfg.TimeoutSecs) * time.Second
	if to <= 0 {
		to = 45 * time.Second
	}
	return &anthropicVerifier{
		model:   model,
		baseURL: base,
		apiKey:  apiKey(cfg),
		timeout: to,
		// No client timeout: we govern deadlines via context so cancellation
		// from the caller is honored precisely.
		client: &http.Client{},
	}
}

// Name identifies this verifier in logs and verdicts.
func (a *anthropicVerifier) Name() string { return "anthropic" }

// cacheScope keys the persistent verdict cache. It includes the model: a
// different model is a different judge, and its verdicts must not be inherited.
func (a *anthropicVerifier) cacheScope() string { return "anthropic:" + a.model }

// anthropicRequest is the subset of the Messages API body we populate.
type anthropicRequest struct {
	Model        string             `json:"model"`
	MaxTokens    int                `json:"max_tokens"`
	System       string             `json:"system"`
	Messages     []anthropicMessage `json:"messages"`
	OutputConfig map[string]any     `json:"output_config,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicResponse captures just the content blocks and any API error.
type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Verify classifies the whole batch in a single request and maps the structured
// output back to one Verdict per request, in order.
func (a *anthropicVerifier) Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	if a.apiKey == "" {
		return nil, fmt.Errorf("anthropic: API key not set")
	}

	reqBody := anthropicRequest{
		Model:     a.model,
		MaxTokens: maxTokensFor(len(batch)),
		System:    systemPrompt,
		Messages:  []anthropicMessage{{Role: "user", Content: buildUserPrompt(batch)}},
		OutputConfig: map[string]any{
			"format": map[string]any{
				"type":   "json_schema",
				"schema": resultSchema(),
			},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("anthropic: marshal request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	header := http.Header{}
	header.Set("x-api-key", a.apiKey)
	header.Set("anthropic-version", anthropicVersion)
	header.Set("content-type", "application/json")

	resp, err := postJSON(ctx, a.client, "anthropic", a.baseURL+"/v1/messages", raw, header)
	if err != nil {
		return nil, err
	}
	if resp.status != http.StatusOK {
		return nil, fmt.Errorf("anthropic: HTTP %d: %s", resp.status, trimBody(resp.body))
	}

	var ar anthropicResponse
	if err := json.Unmarshal(resp.body, &ar); err != nil {
		return nil, fmt.Errorf("anthropic: decode response: %w", err)
	}
	if ar.Error != nil {
		return nil, fmt.Errorf("anthropic: api error: %s: %s", ar.Error.Type, ar.Error.Message)
	}

	text := firstText(ar)
	if text == "" {
		return nil, fmt.Errorf("anthropic: response contained no text content block")
	}
	br, err := parseBatchResults(text)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}
	return mapResults(batch, br, "anthropic:"+a.model), nil
}

// firstText returns the first text content block, the location of our JSON.
func firstText(ar anthropicResponse) string {
	for _, c := range ar.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text
		}
	}
	return ""
}

// parseBatchResults decodes the model's JSON. It tolerates the JSON being
// wrapped in prose or a ```json fence by extracting the outermost object.
func parseBatchResults(text string) (batchResults, error) {
	var br batchResults
	s := extractJSONObject(text)
	if s == "" {
		return br, fmt.Errorf("no JSON object in model output")
	}
	if err := json.Unmarshal([]byte(s), &br); err != nil {
		return br, fmt.Errorf("parse model JSON: %w", err)
	}
	return br, nil
}

// extractJSONObject returns the substring from the first '{' to the last '}'.
// Structured outputs return bare JSON, but chat/JSON-mode fallbacks may add a
// fence or whitespace; this keeps parsing robust without a full tokenizer.
func extractJSONObject(s string) string {
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end <= start {
		return ""
	}
	return s[start : end+1]
}
