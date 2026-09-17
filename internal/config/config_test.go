package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"*.env", "config.env", true},
		{"*.env", "sub/config.env", true}, // basename glob
		{"*.min.js", "a/b/app.min.js", true},
		{"node_modules/**", "node_modules/x/y.js", true},
		{"**/*.go", "a/b/c.go", true},
		{"testdata/**", "testdata/leaky.env", true},
		{"testdata/**", "src/testdata/leaky.env", true}, // suffix-aligned
		{"docs/*.md", "docs/guide.md", true},
		{"docs/*.md", "docs/sub/guide.md", false}, // * doesn't cross /
		{"vendor/**", "internal/vendor/x", true},
		{"*.go", "main.rs", false},
		{"src/*.go", "lib/main.go", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestDefaultIgnores(t *testing.T) {
	c := Default()
	for _, p := range []string{
		".git/config", "node_modules/lodash/index.js", "vendor/x/y.go",
		"app.min.js", "go.sum", "package-lock.json", "image.png", "a/b/logo.svg",
	} {
		if !c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"main.go", "src/config.py", "README2.txt"} {
		if c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = true, want false", p)
		}
	}
}

func TestAllowlists(t *testing.T) {
	c := Default()
	c.Allowlist.Paths = []string{"testdata/**", "**/*_test.go"}
	c.Allowlist.Regexes = []string{`^AKIA[A-Z0-9]{16}$`}
	c.Allowlist.Fingerprints = []string{"abc123"}
	if err := c.compile(); err != nil {
		t.Fatal(err)
	}
	if !c.PathAllowlisted("testdata/x.env") || !c.PathAllowlisted("internal/foo_test.go") {
		t.Error("expected path allowlist hits")
	}
	if c.PathAllowlisted("internal/foo.go") {
		t.Error("unexpected path allowlist hit")
	}
	if !c.SecretAllowlisted("AKIAIOSFODNN7EXAMPLE") {
		t.Error("secret regex allowlist should match")
	}
	if c.SecretAllowlisted("ghp_realtoken") {
		t.Error("secret regex should not match unrelated value")
	}
	if !c.FingerprintAllowlisted("abc123") || c.FingerprintAllowlisted("zzz") {
		t.Error("fingerprint allowlist mismatch")
	}
}

func TestStopwordsMerged(t *testing.T) {
	c := Default()
	c.Allowlist.Stopwords = []string{"acme-internal"}
	sw := c.Stopwords()
	var hasBuiltin, hasCustom bool
	for _, w := range sw {
		if w == "example" {
			hasBuiltin = true
		}
		if w == "acme-internal" {
			hasCustom = true
		}
	}
	if !hasBuiltin || !hasCustom {
		t.Errorf("Stopwords must merge builtin + custom; got %v", sw)
	}
}

func TestLoadOverlayAndNormalize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".klarion.toml")
	toml := `
[entropy]
alpha = 3.0
min_length = 8
threshold = 0.9

[ai]
mode = "off"
model = "claude-haiku-4-5"

[allowlist]
paths = ["secrets/**"]
`
	if err := os.WriteFile(path, []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Entropy.Alpha != 3.0 {
		t.Errorf("alpha = %v, want 3.0", c.Entropy.Alpha)
	}
	if c.Entropy.MinLength < 16 {
		t.Errorf("min_length must be clamped to >=16, got %d", c.Entropy.MinLength)
	}
	if c.AI.Mode != "off" {
		t.Errorf("ai.mode = %q", c.AI.Mode)
	}
	if !c.PathAllowlisted("secrets/prod.env") {
		t.Error("overlaid allowlist not applied")
	}
	// Defaults survive where not overridden.
	if c.Report.Format != "text" {
		t.Errorf("report.format default lost: %q", c.Report.Format)
	}
}

func TestLoadUnknownKeyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".klarion.toml")
	if err := os.WriteFile(path, []byte("[entropy]\nbogus_key = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected error on unknown config key")
	}
}

func TestFindAndLoadWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".klarion.toml"), []byte("[ai]\nmode=\"off\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KLARION_CONFIG", "")
	c, src, err := FindAndLoad(deep)
	if err != nil {
		t.Fatal(err)
	}
	if src == "" {
		t.Error("expected to discover config walking up")
	}
	if c.AI.Mode != "off" {
		t.Errorf("discovered config not loaded: mode=%q", c.AI.Mode)
	}
}

func TestOllamaBaseURLDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".klarion.toml")
	if err := os.WriteFile(path, []byte("[ai]\nprovider=\"ollama\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.AI.BaseURL == "" {
		t.Error("ollama provider should default a base URL")
	}
}

// Klarion's own state files are full of hex digests — verdict-cache keys and
// baseline fingerprints — which read as high-entropy tokens. Scanning them made
// every run report the previous run's bookkeeping as fresh secrets, and the
// count grew on each run.
func TestDefaultIgnoresKlarionState(t *testing.T) {
	c := Default()
	for _, p := range []string{
		".klarion/verdicts.json",
		".klarion/cache/anything.json",
		".klarion-baseline.json",
		".klarion.toml",
		"services/api/klarion.toml",
	} {
		if !c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = false, want true", p)
		}
	}
	// Not so broad that it swallows a user's own files.
	for _, p := range []string{
		"klarion.go",
		"internal/klarion/config.go",
		"docs/klarion-setup.md",
	} {
		if c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = true, want false", p)
		}
	}
}

// TestDefaultIgnoresEncodedBlobs: a base64-encoded binary is maximum entropy by
// construction and never a credential. symfony's favicon.png.base64 produced
// five candidates the model could only call "uncertain" -- and uncertain is
// kept, so they landed in the report. The image-extension ignores miss these
// because the encoding extension comes last.
func TestDefaultIgnoresEncodedBlobs(t *testing.T) {
	c := Default()
	if err := c.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, p := range []string{
		"src/Symfony/Component/ErrorHandler/Resources/assets/images/favicon.png.base64",
		"assets/logo.b64",
	} {
		if !c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = false, want true", p)
		}
	}
	// Ordinary source must still be scanned.
	for _, p := range []string{"internal/config/config.go", "src/app/main.php"} {
		if c.PathIgnored(p) {
			t.Errorf("PathIgnored(%q) = true, want false", p)
		}
	}
}

func TestMaxDecodeDepth(t *testing.T) {
	if got := Default().Scan.MaxDecodeDepth; got != 2 {
		t.Errorf("default max_decode_depth = %d, want 2", got)
	}
	for in, want := range map[int]int{-1: 0, 0: 0, 3: 3, 99: 5} {
		c := Default()
		c.Scan.MaxDecodeDepth = in
		c.normalize()
		if c.Scan.MaxDecodeDepth != want {
			t.Errorf("normalize(%d) = %d, want %d", in, c.Scan.MaxDecodeDepth, want)
		}
	}
}
