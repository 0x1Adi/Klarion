package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
)

// A provider must only ever read the environment variable that belongs to it.
// Before this was enforced, config.Default() carried api_key_env =
// "ANTHROPIC_API_KEY" for every provider, so `provider = "openai"` authenticated
// against api.openai.com with the operator's Anthropic key.
func TestKeyEnvIsProviderScoped(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		explicit string // ai.api_key_env
		want     string
	}{
		{"anthropic default", "anthropic", "", "ANTHROPIC_API_KEY"},
		{"empty provider defaults to anthropic", "", "", "ANTHROPIC_API_KEY"},
		{"openai default", "openai", "", "OPENAI_API_KEY"},
		{"ollama needs no key", "ollama", "", ""},
		{"claude-cli needs no key", "claude-cli", "", ""},
		{"explicit override wins", "openai", "MY_GATEWAY_KEY", "MY_GATEWAY_KEY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.AIConfig{Provider: tc.provider, APIKeyEnv: tc.explicit}
			if got := keyEnvName(cfg); got != tc.want {
				t.Errorf("keyEnvName = %q, want %q", got, tc.want)
			}
		})
	}
}

// End-to-end guard on the same bug: with only an Anthropic key exported, an
// OpenAI-compatible endpoint must receive no Authorization header at all.
func TestOpenAIDoesNotSendAnthropicKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-leave-this-process")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"results\":[]}"}}]}`))
	}))
	defer srv.Close()

	cfg := &config.AIConfig{Provider: "openai", BaseURL: srv.URL, MaxBatch: 8}
	v := newOpenAI(cfg)
	if _, err := v.Verify(context.Background(), []Request{{RuleID: "r", Secret: "candidate"}}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization header = %q; the Anthropic key must not reach an OpenAI endpoint", gotAuth)
	}
}

// The openai provider must still authenticate when its own key is present.
func TestOpenAISendsItsOwnKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-openai-key")

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"results\":[]}"}}]}`))
	}))
	defer srv.Close()

	v := newOpenAI(&config.AIConfig{Provider: "openai", BaseURL: srv.URL})
	if _, err := v.Verify(context.Background(), []Request{{RuleID: "r", Secret: "candidate"}}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if want := "Bearer sk-openai-key"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

// hasCredentials drives ai.mode=auto's silent fallback to the offline
// heuristic, so it must not report "credentials available" on the strength of
// another provider's key.
func TestHasCredentialsIsProviderScoped(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-key")
	t.Setenv("OPENAI_API_KEY", "")

	if !hasCredentials(&config.AIConfig{Provider: "anthropic"}) {
		t.Error("anthropic should have credentials when ANTHROPIC_API_KEY is set")
	}
	if hasCredentials(&config.AIConfig{Provider: "openai"}) {
		t.Error("openai must not count an Anthropic key as its credentials")
	}
}

// The Anthropic provider reads its key through the same resolver, so pointing
// api_key_env elsewhere must actually change which variable is read.
func TestAnthropicHonorsExplicitKeyEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-default")
	t.Setenv("CUSTOM_ANTHROPIC_KEY", "sk-ant-custom")

	v := newAnthropic(&config.AIConfig{Provider: "anthropic", APIKeyEnv: "CUSTOM_ANTHROPIC_KEY"})
	if v.apiKey != "sk-ant-custom" {
		t.Errorf("apiKey = %q, want the value of CUSTOM_ANTHROPIC_KEY", v.apiKey)
	}
}
