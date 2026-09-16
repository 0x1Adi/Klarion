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

// defaultOpenAIBaseURL is the public OpenAI API host. Local gateways and
// Ollama override this via ai.base_url (e.g. http://localhost:11434/v1).
const defaultOpenAIBaseURL = "https://api.openai.com/v1"

// openaiVerifier targets any OpenAI-compatible /chat/completions endpoint:
// OpenAI itself, Ollama, vLLM, LiteLLM, and similar gateways. Raw net/http, no
// SDK. The API key may be empty (Ollama and some local gateways need none).
type openaiVerifier struct {
	model   string
	baseURL string
	apiKey  string
	timeout time.Duration
	client  *http.Client
}

// newOpenAI builds a verifier from config. baseURL is normalized to include the
// /v1 prefix expected by the chat/completions path.
func newOpenAI(cfg *config.AIConfig) *openaiVerifier {
	model := cfg.Model
	if model == "" {
		// A widely available small default; overridable via ai.model.
		model = "gpt-4o-mini"
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = defaultOpenAIBaseURL
	}
	// Resolved through keyEnvName: an OpenAI-compatible endpoint must never be
	// handed another provider's key just because one happens to be exported.
	key := apiKey(cfg)
	to := time.Duration(cfg.TimeoutSecs) * time.Second
	if to <= 0 {
		to = 45 * time.Second
	}
	return &openaiVerifier{
		model:   model,
		baseURL: base,
		apiKey:  key,
		timeout: to,
		client:  &http.Client{},
	}
}

// Name identifies this verifier in logs and verdicts.
func (o *openaiVerifier) Name() string { return "openai" }

// cacheScope keys the persistent verdict cache (see anthropicVerifier).
func (o *openaiVerifier) cacheScope() string { return "openai:" + o.model }

type openaiRequest struct {
	Model          string          `json:"model"`
	Messages       []openaiMessage `json:"messages"`
	ResponseFormat map[string]any  `json:"response_format,omitempty"`
	Temperature    float64         `json:"temperature"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// Verify classifies the whole batch with a single chat/completions call using
// JSON mode, then maps choices[0].message.content back to one Verdict per
// request in order.
func (o *openaiVerifier) Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	if len(batch) == 0 {
		return nil, nil
	}

	reqBody := openaiRequest{
		Model: o.model,
		Messages: []openaiMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUserPrompt(batch)},
		},
		// JSON mode: the model is constrained to emit a single JSON object.
		// The exact shape is dictated by systemPrompt (json_object mode does
		// not accept a schema across all compatible backends).
		ResponseFormat: map[string]any{"type": "json_object"},
		Temperature:    0,
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("openai: marshal request: %w", err)
	}

	header := http.Header{}
	header.Set("content-type", "application/json")
	// Ollama / some local gateways require no auth; only send a bearer when set.
	if o.apiKey != "" {
		header.Set("Authorization", "Bearer "+o.apiKey)
	}

	resp, err := postJSON(ctx, o.client, "openai", o.baseURL+"/chat/completions", raw, header, o.timeout)
	if err != nil {
		return nil, err
	}
	if resp.status != http.StatusOK {
		return nil, fmt.Errorf("openai: HTTP %d: %s", resp.status, trimBody(resp.body))
	}

	var or openaiResponse
	if err := json.Unmarshal(resp.body, &or); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	if or.Error != nil {
		return nil, fmt.Errorf("openai: api error: %s: %s", or.Error.Type, or.Error.Message)
	}
	if len(or.Choices) == 0 {
		return nil, fmt.Errorf("openai: response contained no choices")
	}
	br, err := parseBatchResults(or.Choices[0].Message.Content)
	if err != nil {
		return nil, fmt.Errorf("openai: %w", err)
	}
	return mapResults(batch, br, "openai:"+o.model), nil
}
