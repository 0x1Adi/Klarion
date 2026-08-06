package verify

import (
	"context"
	"regexp"
	"strings"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// heuristicVerifier is the offline fallback used when AI is disabled (mode=off)
// or no credentials are available. It never touches the network and is fully
// deterministic, so its verdicts are reproducible and testable. Because this is
// a security tool, its default when signals are inconclusive is VerdictUncertain
// (which downstream treats as a secret), never a silent false-positive.
type heuristicVerifier struct{}

// newHeuristic constructs the offline verifier.
func newHeuristic() *heuristicVerifier { return &heuristicVerifier{} }

// Name identifies this verifier in logs and verdicts.
func (h *heuristicVerifier) Name() string { return "heuristic" }

// highEntropy is the normalized-score floor above which a token looks
// statistically random (matches the entropy package's discrimination band).
const highEntropy = 0.85

// placeholderMarkers are lowercase substrings that, when present in the
// candidate value itself, all but guarantee it is a fixture/placeholder.
var placeholderMarkers = []string{
	"example", "sample", "dummy", "placeholder", "changeme", "change-me",
	"change_me", "your_", "your-", "yourkey", "insert_", "replaceme",
	"replace_me", "redacted", "fakekey", "fake_key", "fake-key", "notreal",
	"not_a_real", "fixme", "lorem", "ipsum", "foobar", "test1234",
	"password123", "passw0rd", "secret123", "deadbeef", "xxxxxx",
}

// nonProdDirs are path segments that mark a test/example/documentation tree.
// They are matched against whole slash-separated segments, never as
// substrings: a substring match treated "latest/" as a test directory (it
// contains "test") and silently discarded real credentials underneath it.
var nonProdDirs = map[string]bool{
	"test": true, "tests": true, "testing": true, "testdata": true,
	"__tests__": true, "spec": true, "specs": true,
	"example": true, "examples": true, "sample": true, "samples": true,
	"fixture": true, "fixtures": true, "mock": true, "mocks": true,
	"__mocks__": true, "doc": true, "docs": true,
	"tutorial": true, "tutorials": true,
}

// nonProdFileTokens mark a *file name* as a test or example artifact when they
// appear as a whole token: "client_test.go", "api.spec.ts", "example.env".
// Tokens are split on the separators real file names use, so "manifest.json"
// and "latest.json" are not caught.
var nonProdFileTokens = map[string]bool{
	"test": true, "tests": true, "spec": true, "specs": true,
	"example": true, "examples": true, "sample": true, "samples": true,
	"fixture": true, "fixtures": true, "mock": true, "mocks": true,
	"readme": true, "changelog": true, "swagger": true, "openapi": true,
}

// codeContextMarkers are the only markers strong enough to judge a candidate by
// its *surrounding lines* rather than its location. Deliberately narrow: the
// context window is a few lines wide, so a weak marker like "test" or "spec"
// appearing anywhere near a credential ("// see the spec", a URL ending in
// /latest) was enough to discard a real leak. These are all words that describe
// the value itself, and they are matched on word boundaries.
var codeContextMarkers = []string{
	"fixture", "dummy", "placeholder", "for testing", "test only",
	"not a real", "sample value",
}

var codeContextRe = regexp.MustCompile(`\b(` + strings.Join(codeContextMarkers, "|") + `)\b`)

// knownPrefixes are unambiguous credential prefixes: their presence is strong
// evidence of a real key regardless of entropy.
var knownPrefixes = []string{
	"AKIA", "ASIA", "sk-", "sk_live_", "sk_test_", "pk_live_", "rk_live_",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"xoxb-", "xoxp-", "xoxa-", "xoxr-", "AIza", "ya29.", "SG.", "SK",
	"npm_", "dop_v1_", "shpss_", "shpat_", "-----BEGIN",
}

var (
	// uuidRe matches a canonical UUID — a non-secret identifier.
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// hex40Re matches a git-sha-shaped 40-char hex digest.
	hex40Re = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

// Verify classifies each request independently and deterministically.
func (h *heuristicVerifier) Verify(_ context.Context, batch []Request) ([]finding.Verdict, error) {
	out := make([]finding.Verdict, len(batch))
	for i, r := range batch {
		out[i] = h.classify(r)
	}
	return out, nil
}

func (h *heuristicVerifier) classify(r Request) finding.Verdict {
	const name = "heuristic"
	sec := r.Secret
	if sec == "" {
		return finding.Verdict{Status: finding.VerdictUncertain, Confidence: 0.3,
			Reason: "no secret value to inspect", Verifier: name}
	}
	lowerSec := strings.ToLower(sec)
	generic := isGenericRule(r.RuleID)

	// 1. A placeholder marker inside the value is decisive, whatever the rule.
	if containsAny(lowerSec, placeholderMarkers) {
		return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.9,
			Reason: "value contains a placeholder/example marker", Verifier: name}
	}

	// 1b. Structural suppressors: comment lines, RDoc markup, non-literal
	//     assignments, digest constants and placeholder credentials. These key
	//     off code structure rather than entropy, which is what makes the
	//     credential-free (heuristic-only) path usable in CI. See suppress.go.
	if reason := structuralFP(r, generic); reason != "" {
		return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.85,
			Reason: reason, Verifier: name}
	}

	// 2. Non-secret identifier shapes.
	if uuidRe.MatchString(sec) {
		return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.85,
			Reason: "value is a UUID, not a credential", Verifier: name}
	}
	if generic && hex40Re.MatchString(sec) {
		return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.7,
			Reason: "value is a git-sha-like 40-char hex digest", Verifier: name}
	}

	// 3. A generic (entropy-only) match inside a test/example/docs context is
	//    very likely a fixture.
	if generic && contextLooksNonProd(r) {
		return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.75,
			Reason: "generic high-entropy match inside test/example/docs context", Verifier: name}
	}

	// 4. A specific rule fired: trust the pattern. Confidence rises with a
	//    recognized credential prefix or high entropy.
	if !generic {
		conf := 0.7
		reason := "matched a specific detection rule"
		if hasKnownPrefix(sec) {
			conf, reason = 0.95, "matched a specific rule with a known credential prefix"
		} else if r.Entropy >= highEntropy {
			conf, reason = 0.9, "matched a specific rule with high-entropy value"
		}
		return finding.Verdict{Status: finding.VerdictSecret, Confidence: conf,
			Reason: reason, Verifier: name}
	}

	// 5. Generic value with no disqualifying signals: cannot decide offline.
	//    Uncertain is the safe default (treated as a secret downstream).
	reason := "generic candidate; offline heuristics cannot decide"
	conf := 0.4
	if r.Entropy >= highEntropy {
		reason = "high-entropy generic value with no false-positive signals; needs review"
		conf = 0.5
	}
	return finding.Verdict{Status: finding.VerdictUncertain, Confidence: conf,
		Reason: reason, Verifier: name}
}

// isGenericRule reports whether a rule id denotes an entropy-only (non-pattern)
// finding, which carries the weakest provenance.
func isGenericRule(id string) bool {
	return id == "" || strings.HasPrefix(id, "generic")
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func hasKnownPrefix(sec string) bool {
	for _, p := range knownPrefixes {
		if strings.HasPrefix(sec, p) {
			return true
		}
	}
	return false
}

// contextLooksNonProd reports whether a candidate lives somewhere that makes it
// a fixture rather than a credential: a test/example/docs path, or surrounding
// code that says so outright.
func contextLooksNonProd(r Request) bool {
	return pathLooksNonProd(r.FilePath) || codeContextRe.MatchString(strings.ToLower(r.Context))
}

// pathLooksNonProd matches a path against directory segments and file-name
// tokens rather than raw substrings.
func pathLooksNonProd(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 {
		return false
	}
	for _, seg := range segs[:len(segs)-1] {
		if nonProdDirs[seg] {
			return true
		}
	}
	base := segs[len(segs)-1]
	if isDocFile(base) { // prose formats (.md/.rst/.adoc/...) — see suppress.go
		return true
	}
	for _, tok := range strings.FieldsFunc(base, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	}) {
		if nonProdFileTokens[tok] {
			return true
		}
	}
	return false
}
