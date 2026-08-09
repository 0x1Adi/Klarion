// Package finding defines the core data types shared by every Klarion
// component: findings, severities, and AI verification verdicts.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Severity classifies how dangerous a leaked secret is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Rank returns a numeric rank for severity comparison; higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// ParseSeverity parses a severity string (case-insensitive). Unknown values
// fall back to SeverityLow so a bad config never silently raises the bar.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// VerdictStatus is the outcome of AI (or heuristic) verification.
type VerdictStatus string

const (
	// VerdictUnverified means no verifier has adjudicated the finding yet.
	VerdictUnverified VerdictStatus = "unverified"
	// VerdictSecret means the verifier judged this a real leaked secret.
	VerdictSecret VerdictStatus = "secret"
	// VerdictFalsePositive means the verifier judged this a false positive
	// (placeholder, test fixture, documentation example, non-secret ID, ...).
	VerdictFalsePositive VerdictStatus = "false_positive"
	// VerdictUncertain means the verifier could not decide; treat as a secret.
	VerdictUncertain VerdictStatus = "uncertain"
)

// Verdict records the result of the verification stage for one finding.
type Verdict struct {
	Status     VerdictStatus `json:"status"`
	Confidence float64       `json:"confidence,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	Verifier   string        `json:"verifier,omitempty"`
}

// Finding is one detected candidate secret.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	FilePath    string   `json:"file"`
	Line        int      `json:"line"`
	Column      int      `json:"column,omitempty"`     // 1-based byte offset of the secret in the line
	EndColumn   int      `json:"end_column,omitempty"` // 1-based, exclusive
	LineText    string   `json:"-"`                    // full line text (may contain the raw secret)
	Secret      string   `json:"-"`                    // raw secret — never serialized
	Redacted    string   `json:"secret_redacted"`
	Entropy     float64  `json:"entropy,omitempty"`      // normalized Rényi score (≈1.0 = indistinguishable from random)
	EntropyBits float64  `json:"entropy_bits,omitempty"` // absolute H_α in bits
	Severity    Severity `json:"severity"`
	Context     string   `json:"-"` // surrounding lines, used by the AI verifier
	Commit      string   `json:"commit,omitempty"`
	Author      string   `json:"author,omitempty"`
	Email       string   `json:"email,omitempty"`
	Date        string   `json:"date,omitempty"`
	Message     string   `json:"commit_message,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Verdict     Verdict  `json:"verdict"`
	Occurrences int      `json:"occurrences,omitempty"` // source lines this one credential spans (wrapped key blocks)
	Tags        []string `json:"tags,omitempty"`
	Suppressed  bool     `json:"suppressed,omitempty"` // true when baseline/allowlist suppressed it
}

// ComputeFingerprint derives a stable fingerprint for the finding: it survives
// line-number drift and history rewrites because it hashes only the rule, the
// path, and a digest of the secret itself.
func (f *Finding) ComputeFingerprint() string {
	sec := sha256.Sum256([]byte(f.Secret))
	h := sha256.New()
	h.Write([]byte(f.RuleID))
	h.Write([]byte{0})
	h.Write([]byte(f.FilePath))
	h.Write([]byte{0})
	h.Write(sec[:])
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Redact masks a secret for display. The mask has a fixed width so the true
// length of the secret is not leaked.
func Redact(secret string) string {
	n := len(secret)
	switch {
	case n == 0:
		return ""
	case n < 8:
		return "****"
	case n < 16:
		return secret[:2] + "****"
	default:
		return secret[:4] + "****" + secret[n-4:]
	}
}

// RedactInText replaces every occurrence of secret inside text with its
// redacted form. Used to sanitize context snippets before they leave the
// process (reports, MCP responses, hook output).
func RedactInText(text, secret string) string {
	if secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, Redact(secret))
}
