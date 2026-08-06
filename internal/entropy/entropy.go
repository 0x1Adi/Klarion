// Package entropy implements Rényi entropy scoring for secret detection.
//
// Klarion's fast pass scores candidate tokens with the Rényi entropy of order
// α (default α = 2, the "collision entropy"), normalized against the expected
// entropy of a uniformly random string of the same length drawn from the same
// character class. The normalized score is what makes thresholds portable
// across token lengths and alphabets: a value near 1.0 means the token is
// statistically indistinguishable from random — exactly what real keys look
// like — while natural language, identifiers, and paths score visibly lower.
//
// Why Rényi over plain Shannon: for α > 1 the entropy is dominated by the
// most probable symbols, so it penalizes the skewed character distributions
// of human-produced text more sharply than Shannon does, while the α
// parameter stays user-tunable (α → 1 recovers Shannon exactly).
package entropy

import "math"

// Renyi returns the Rényi entropy of order alpha, in bits, of the empirical
// byte distribution of s.
//
//	H_α(s) = 1/(1-α) · log2( Σᵢ pᵢ^α )        for α ≠ 1
//	H_1(s) = -Σᵢ pᵢ·log2(pᵢ)                  (Shannon, the α → 1 limit)
//
// alpha must be > 0; values within 1e-9 of 1 are treated as Shannon.
// Strings shorter than 2 bytes score 0.
func Renyi(s string, alpha float64) float64 {
	if len(s) < 2 || alpha <= 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))

	if math.Abs(alpha-1) < 1e-9 {
		var h float64
		for _, c := range counts {
			if c == 0 {
				continue
			}
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
		return h
	}

	var sum float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		sum += math.Pow(p, alpha)
	}
	if sum <= 0 {
		return 0
	}
	return math.Log2(sum) / (1 - alpha)
}

// Shannon is Renyi with α = 1.
func Shannon(s string) float64 { return Renyi(s, 1) }

// Charset describes the smallest common character class of a token.
type Charset struct {
	Name string
	Size int
}

var (
	CharsetDigits    = Charset{"digits", 10}
	CharsetHex       = Charset{"hex", 16}
	CharsetLower     = Charset{"lower", 26}
	CharsetUpper     = Charset{"upper", 26}
	CharsetLowerNum  = Charset{"lowernum", 36}
	CharsetUpperNum  = Charset{"uppernum", 36}
	CharsetAlpha     = Charset{"alpha", 52}
	CharsetAlphaNum  = Charset{"alphanum", 62}
	CharsetBase64    = Charset{"base64", 64}
	CharsetPrintable = Charset{"printable", 94}
)

// Classify returns the smallest character class containing every byte of s.
// Hex is only reported when the letter case is consistent (mixed-case
// hex-looking strings are treated as the wider alphanumeric class).
func Classify(s string) Charset {
	var hasLower, hasUpper, hasDigit, hasB64Sym, hasOther bool
	hexLower, hexUpper := true, true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'a' && c <= 'z':
			hasLower = true
			if c > 'f' {
				hexLower = false
			}
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			if c > 'F' {
				hexUpper = false
			}
		case c == '+' || c == '/' || c == '=' || c == '-' || c == '_':
			hasB64Sym = true
		default:
			hasOther = true
		}
	}
	switch {
	case hasOther:
		return CharsetPrintable
	case hasB64Sym:
		return CharsetBase64
	case hasDigit && !hasLower && !hasUpper:
		return CharsetDigits
	case hasDigit && hasLower && !hasUpper && hexLower:
		return CharsetHex
	case hasDigit && hasUpper && !hasLower && hexUpper:
		return CharsetHex
	case hasLower && hasUpper && hasDigit:
		return CharsetAlphaNum
	case hasLower && hasUpper:
		return CharsetAlpha
	case hasLower && hasDigit:
		return CharsetLowerNum
	case hasUpper && hasDigit:
		return CharsetUpperNum
	case hasLower:
		return CharsetLower
	default:
		return CharsetUpper
	}
}

// ExpectedCollision returns a deterministic estimate, in bits, of the
// collision (order-2 Rényi) entropy of a uniformly random string of length n
// over an alphabet of k symbols. It uses the exact expectation of the
// empirical collision probability,
//
//	E[ Σᵢ p̂ᵢ² ] = 1/n + (n-1)/(n·k),
//
// which by Jensen's inequality gives a slightly conservative (low) estimate
// of E[H₂] — a stable, closed-form normalizer for finite samples.
func ExpectedCollision(n, k int) float64 {
	if n < 2 || k < 2 {
		return 0
	}
	c := 1/float64(n) + float64(n-1)/(float64(n)*float64(k))
	return -math.Log2(c)
}

// NormalizedScore returns H₂(s) divided by the expected collision entropy of
// a random string of the same length and character class. Values cluster
// near 1.0 for machine-generated keys and fall off for human-produced text.
// The score is clamped to [0, 1.25] to bound the effect of sampling noise.
func NormalizedScore(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	cs := Classify(s)
	exp := ExpectedCollision(len(s), cs.Size)
	if exp <= 0 {
		return 0
	}
	score := Renyi(s, 2) / exp
	if score < 0 {
		return 0
	}
	if score > 1.25 {
		return 1.25
	}
	return score
}
