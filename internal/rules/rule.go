// Package rules defines Klarion's detection rule model and the built-in
// curated ruleset (see builtin.go).
package rules

import (
	"regexp"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// Rule is a single pattern-based detector. Rules run per line: a cheap
// keyword prescreen gates the (more expensive) regex, and an optional
// normalized-entropy floor filters structureless matches.
type Rule struct {
	// ID is the stable kebab-case identifier, e.g. "aws-access-key-id".
	ID string
	// Description is a short human-readable explanation of what leaked.
	Description string
	// Regex matches the secret within a single line.
	Regex *regexp.Regexp
	// SecretGroup is the capture group index holding the secret; 0 means the
	// entire match.
	SecretGroup int
	// Keywords are lowercase substrings; at least one must appear in the
	// lowercased line for the regex to run. Empty means always run.
	Keywords []string
	// Entropy, when > 0, is the minimum normalized Rényi score
	// (entropy.NormalizedScore) the captured secret must reach.
	Entropy float64
	// MinLen/MaxLen bound the secret length; 0 means unbounded.
	MinLen, MaxLen int
	// Severity assigned to findings from this rule.
	Severity finding.Severity
	// Tags for grouping/reporting (e.g. "cloud", "vcs", "ai").
	Tags []string
	// Allowlist regexes: if any matches the captured secret, the finding is
	// dropped (rule-specific false-positive guards).
	Allowlist []*regexp.Regexp
}
