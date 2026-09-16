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
const systemPrompt = `You are a secret-verification classifier inside a static code scanner.

You have NO access to the repository, no tools, and no ability to read files or run
commands. Do not attempt to. Every candidate arrives with all the metadata needed to
judge it. If a field is missing, treat it as unknown rather than investigating.

INPUT. Each candidate is a JSON object:
  index         stable id you must echo back
  rule_id       which detector fired (e.g. aws-access-key, generic-high-entropy)
  description   what that rule looks for
  file          repository-relative path
  line          line number of the match
  secret        the matched value (may arrive redacted as abc...xyz)
  context       surrounding source lines
  entropy       0..1 normalized; ~1.0 is indistinguishable from random
  is_test_path  true when the file sits under a test / fixture / example tree
  block_type    "key_block" = one wrapped credential spanning many lines
                "single_line" = an inline value
  occurrences   how many source lines this one credential spans

DECISION PROCEDURE. Apply in order; stop at the first rule that matches.

1. Structurally a credential? A named token format (AKIA..., ghp_..., sk-...,
   xox?-..., AIza..., -----BEGIN ... PRIVATE KEY-----). If yes and is_test_path is
   true, go to rule 5; otherwise "secret".
2. Structurally a NON-secret identifier? UUID, git SHA, semver, content hash
   (sha256-/sha384-/integrity=), a PUBLIC key or certificate body, a bcrypt/MD5/
   SHA digest, or base64 that decodes to readable text. -> "false_positive".
3. A language identifier rather than data? A value that is a valid identifier in
   the file's language and reads as a symbol name -- CamelCase, SCREAMING_SNAKE_CASE,
   a function, field, constant or env-var NAME -- is almost never a credential no
   matter how high its entropy. Long identifiers are ordinary in Go, Java, C# and
   JavaScript. -> "false_positive".
4. An obvious placeholder or documentation value? your-api-key, XXXX, changeme,
   <token>, foo/bar, example.com, 000000, lorem. -> "false_positive".
5. Real key material in a test tree? When is_test_path is true AND the path or
   filename says test/sample/example/fixture, a private key or credential there is
   a generated fixture, not a live one -> "false_positive", confidence at most 0.8.
   This applies whether block_type is "key_block" or the key is embedded as a
   string literal inside a test source file (a _test.go, *Tests.java, *.spec.ts).
   If the path carries NO test signal -> "secret".
6. Otherwise weigh entropy against the assignment in context. High entropy assigned
   to a key/token/password/secret/credential name -> "secret". High entropy with no
   credential-like key context -> "uncertain".

BIAS. This is a security tool: a missed leak costs far more than a false alarm.
Where the rules leave you genuinely split, prefer "secret" over "uncertain", and
"uncertain" over "false_positive". Judge each candidate independently.

OUTPUT. Return exactly one JSON object and nothing else -- no markdown fence, no
preamble, no commentary, no trailing text.

{"results":[{"index":0,"status":"secret","confidence":0.95,"reason":"AWS key id assigned to a config field"}]}

  - emit exactly one result object per input candidate, echoing its "index"
  - "status" is exactly one of: secret | false_positive | uncertain
  - "confidence" is a number between 0 and 1
  - "reason" is one sentence, at most 15 words, no newlines and no double quotes
  - if you cannot judge a candidate, still emit it with status "uncertain"`

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

	header := http.Header{}
	header.Set("x-api-key", a.apiKey)
	header.Set("anthropic-version", anthropicVersion)
	header.Set("content-type", "application/json")

	resp, err := postJSON(ctx, a.client, "anthropic", a.baseURL+"/v1/messages", raw, header, a.timeout)
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

	// Fast path: the whole payload is the object we asked for.
	if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &br); err == nil && br.Results != nil {
		return br, nil
	}

	objs := extractJSONObjects(text)
	if len(objs) == 0 {
		// Some models drop the {"results": ...} wrapper and emit the array
		// directly. That is still unambiguous, so accept it.
		if items, err := parseResultArray(text); err == nil {
			return batchResults{Results: items}, nil
		}
		return br, fmt.Errorf("no JSON object in model output (model said: %s)", snippet(text))
	}

	// Merge across objects. A model under JSON mode sometimes splits one batch
	// into several concatenated objects; taking only the first would silently
	// drop verdicts, which then resolve as "uncertain" and are reported as
	// findings. Merging keeps every verdict the model actually produced.
	var merged []batchResult
	var firstErr error
	for _, o := range objs {
		var one batchResults
		if err := json.Unmarshal([]byte(o), &one); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(one.Results) > 0 {
			merged = append(merged, one.Results...)
			continue
		}
		// A model that drops the {"results": ...} wrapper entirely and emits the
		// verdict objects on their own -- observed from Groq's
		// openai/gpt-oss-20b, one bare object per candidate. Unwrapped is still
		// unambiguous: a "status" field is what makes it a verdict rather than
		// some other object that happened to parse.
		var item batchResult
		if err := json.Unmarshal([]byte(o), &item); err == nil && item.Status != "" {
			merged = append(merged, item)
		}
	}
	if len(merged) == 0 {
		if items, err := parseResultArray(text); err == nil {
			return batchResults{Results: items}, nil
		}
		if firstErr != nil {
			return br, fmt.Errorf("parse model JSON: %w (model said: %s)", firstErr, snippet(text))
		}
		return br, fmt.Errorf("no verdicts in model output (model said: %s)", snippet(text))
	}
	br.Results = merged
	return br, nil
}

// snippet renders what the model actually returned, bounded, so a parse failure
// is diagnosable from the error alone. Guessing at the cause of an empty result
// twice was slower than printing it once.
//
// It can contain candidate text, so it goes only into an error the operator
// sees -- never into a report or the verdict cache.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "<empty response>"
	}
	s = strings.Join(strings.Fields(s), " ")
	const max = 220
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// parseResultArray accepts a bare array of result objects, for models that omit
// the {"results": ...} wrapper.
func parseResultArray(text string) ([]batchResult, error) {
	start := strings.IndexByte(text, '[')
	end := strings.LastIndexByte(text, ']')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON array")
	}
	var items []batchResult
	if err := json.Unmarshal([]byte(text[start:end+1]), &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("empty array")
	}
	return items, nil
}

// extractJSONObjects returns every balanced top-level JSON object in s, in
// order, ignoring braces that appear inside string literals.
//
// The previous implementation sliced from the first '{' to the last '}'. That
// works for one object and corrupts everything else: two objects in a row
// became "{...}{...}" or "{...},{...}", which json.Unmarshal rejects with
// "invalid character ',' after top-level value" and, under on_error=fail, kills
// the scan. Observed in practice from an OpenAI-compatible provider in JSON
// mode, so it is a reachable path, not a theoretical one.
//
// Prose, markdown fences and trailing commentary around the objects are all
// tolerated because only balanced brace runs are collected.
func extractJSONObjects(s string) []string {
	var out []string
	depth, start := 0, -1
	inStr, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					out = append(out, s[start:i+1])
					start = -1
				}
			}
		}
	}
	return out
}
