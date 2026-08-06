package entropy

import (
	"math"
	"testing"
)

func almost(t *testing.T, got, want, tol float64, name string) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %v, want %v ± %v", name, got, want, tol)
	}
}

func TestRenyiKnownValues(t *testing.T) {
	// Two symbols, uniform: every Rényi order gives exactly 1 bit.
	almost(t, Renyi("aabb", 2), 1.0, 1e-9, `H2("aabb")`)
	almost(t, Renyi("aabb", 1), 1.0, 1e-9, `H1("aabb")`)
	almost(t, Renyi("aabb", 0.5), 1.0, 1e-9, `H0.5("aabb")`)

	// Four symbols, uniform: 2 bits.
	almost(t, Renyi("abcd", 2), 2.0, 1e-9, `H2("abcd")`)

	// Skewed distribution "aab": p = (2/3, 1/3).
	almost(t, Renyi("aab", 1), 0.9183, 1e-3, `H1("aab")`)
	almost(t, Renyi("aab", 2), 0.8480, 1e-3, `H2("aab")`)
	almost(t, Renyi("aab", 0.5), 0.9581, 1e-3, `H0.5("aab")`)
}

func TestRenyiMonotoneInAlpha(t *testing.T) {
	// Rényi entropy is non-increasing in α for a fixed distribution.
	s := "aabbbcccc1234"
	prev := math.Inf(1)
	for _, a := range []float64{0.25, 0.5, 1, 1.5, 2, 3, 5} {
		h := Renyi(s, a)
		if h > prev+1e-9 {
			t.Errorf("H_%v = %v > H_prev = %v; must be non-increasing", a, h, prev)
		}
		prev = h
	}
}

func TestRenyiEdgeCases(t *testing.T) {
	if Renyi("", 2) != 0 || Renyi("x", 2) != 0 {
		t.Error("short strings must score 0")
	}
	if Renyi("abc", 0) != 0 || Renyi("abc", -1) != 0 {
		t.Error("non-positive alpha must score 0")
	}
	almost(t, Renyi("aaaa", 2), 0, 1e-9, "constant string")
}

func TestExpectedCollision(t *testing.T) {
	// n=32 hex: c = 1/32 + 31/512 = 0.0917969 → 3.4454 bits.
	almost(t, ExpectedCollision(32, 16), 3.4454, 1e-3, "ExpectedCollision(32,16)")
	if ExpectedCollision(1, 16) != 0 || ExpectedCollision(10, 1) != 0 {
		t.Error("degenerate inputs must return 0")
	}
	// More symbols → higher expected entropy; longer strings → higher too.
	if ExpectedCollision(32, 64) <= ExpectedCollision(32, 16) {
		t.Error("larger alphabet should raise expected entropy")
	}
	if ExpectedCollision(64, 16) <= ExpectedCollision(16, 16) {
		t.Error("longer sample should raise expected entropy")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0123456789", "digits"},
		{"deadbeef01", "hex"},
		{"DEADBEEF01", "hex"},
		{"DeadBeef01", "alphanum"}, // mixed-case hex → wider class
		{"abcxyz", "lower"},
		{"ABCXYZ", "upper"},
		{"abc123xyz", "lowernum"},
		{"ABC123XYZ", "uppernum"},
		{"AbCdEfGhZz", "alpha"},
		{"Abc123Xyz9", "alphanum"},
		{"QWJj+MQ==", "base64"},
		{"snake_case_value1", "base64"}, // '_' pushes into base64url class
		{"has space", "printable"},
	}
	for _, c := range cases {
		if got := Classify(c.in); got.Name != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.in, got.Name, c.want)
		}
	}
}

func TestNormalizedScoreDiscrimination(t *testing.T) {
	// Real machine-generated tokens should land near 1.0.
	random := []string{
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", // hex, 40 chars
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY99", // base64-ish, 40 chars (AWS doc example, tweaked)
		"kq8vJ2xR7mZp4Wn1cY6tB3dF9gH5sL0a",         // alphanum, 32 chars
	}
	for _, s := range random {
		if got := NormalizedScore(s); got < 0.85 {
			t.Errorf("NormalizedScore(%q) = %v, want ≥ 0.85 (random-like)", s, got)
		}
	}

	// Human-produced strings must score strictly lower than random ones.
	human := []string{
		"administratorpassword",
		"thisisaverylongsentencewithwords",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	for _, s := range human {
		hs := NormalizedScore(s)
		for _, r := range random {
			if hs >= NormalizedScore(r) {
				t.Errorf("NormalizedScore(%q)=%v should be < NormalizedScore(%q)=%v", s, hs, r, NormalizedScore(r))
			}
		}
	}

	// Degenerate strings score near zero.
	if got := NormalizedScore("aaaaaaaaaaaaaaaaaaaa"); got > 0.1 {
		t.Errorf("constant string scored %v, want ≈ 0", got)
	}
}

func BenchmarkNormalizedScore(b *testing.B) {
	s := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		NormalizedScore(s)
	}
}
