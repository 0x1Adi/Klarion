package verify

import (
	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// Rules returns the decision procedure Klarion's own verifier follows. It is
// handed to a calling agent when Klarion has no provider configured: the agent
// then judges the candidates itself, by the same rules, instead of the scan
// producing no verdict at all.
func Rules() string { return decisionRules }

// Candidates renders findings exactly as a provider would receive them,
// honoring ai.send_secret, so the agent judging them sees the same evidence a
// configured model would: rule, context, entropy, test-path and block metadata.
func Candidates(fs []finding.Finding, cfg *config.AIConfig) []Request {
	out := make([]Request, len(fs))
	for i := range fs {
		out[i] = buildRequest(i, &fs[i], cfg)
	}
	return out
}
