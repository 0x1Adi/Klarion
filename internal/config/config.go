// Package config loads and validates Klarion configuration (.klarion.toml),
// providing compiled path/secret allowlists and defaults tuned for
// production scanning.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the root configuration object. Zero values are not meaningful —
// always start from Default() (Load does this for you).
type Config struct {
	Scan      ScanConfig      `toml:"scan"`
	Entropy   EntropyConfig   `toml:"entropy"`
	Rules     RulesConfig     `toml:"rules"`
	Allowlist AllowlistConfig `toml:"allowlist"`
	AI        AIConfig        `toml:"ai"`
	Report    ReportConfig    `toml:"report"`
	Hook      HookConfig      `toml:"hook"`
	Baseline  BaselineConfig  `toml:"baseline"`

	ignoreRes      []globMatcher
	allowPathRes   []globMatcher
	allowSecretRes []*regexp.Regexp
}

// globMatcher pairs a compiled glob with the pattern it came from. The pattern
// is kept because matching semantics depend on it (a pattern without "/"
// matches the basename), and keeping it on the value rather than in a shared
// side table makes a Config self-contained: no process-wide state to grow
// without bound or to race when two configs compile concurrently.
type globMatcher struct {
	re      *regexp.Regexp
	pattern string
}

type ScanConfig struct {
	// MaxFileSizeBytes: files larger than this are skipped. Default 1 MiB.
	MaxFileSizeBytes int64 `toml:"max_file_size_bytes"`
	// Workers: 0 means runtime.NumCPU().
	Workers        int      `toml:"workers"`
	FollowSymlinks bool     `toml:"follow_symlinks"`
	IgnorePaths    []string `toml:"ignore_paths"` // globs; matched files are not scanned at all
	// MaxDecodeDepth: how many layers of base64/hex/percent/\u encoding are
	// decoded and rescanned. 0 disables decoding. Default 2, capped at 5.
	MaxDecodeDepth int `toml:"max_decode_depth"`
}

type EntropyConfig struct {
	Enabled bool `toml:"enabled"`
	// Alpha is the Rényi order; 2 (collision entropy) is the tuned default,
	// 1 recovers Shannon.
	Alpha     float64 `toml:"alpha"`
	MinLength int     `toml:"min_length"` // clamped to ≥ 16
	MaxLength int     `toml:"max_length"`
	// Threshold is the minimum normalized score for tokens that appear near a
	// secret-ish keyword (password/token/key/...). ThresholdNoContext applies
	// otherwise and should be stricter.
	Threshold          float64 `toml:"threshold"`
	ThresholdNoContext float64 `toml:"threshold_no_context"`
	// RequireDigit: generic candidates must contain ≥1 digit or base64 symbol
	// (kills identifier/camelCase false positives; real keys virtually always
	// contain digits).
	RequireDigit bool `toml:"require_digit"`
}

type RulesConfig struct {
	Disable []string     `toml:"disable"` // rule IDs to turn off
	Custom  []CustomRule `toml:"custom"`
}

// AllowlistConfig suppresses known false positives. Paths are Klarion globs;
// Regexes match against the raw secret; Fingerprints and Stopwords match a
// finding's fingerprint and any case-insensitive substring, respectively.
type AllowlistConfig struct {
	Paths        []string `toml:"paths"`
	Regexes      []string `toml:"regexes"`
	Fingerprints []string `toml:"fingerprints"`
	Stopwords    []string `toml:"stopwords"`
}

type CustomRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	SecretGroup int      `toml:"secret_group"`
	Keywords    []string `toml:"keywords"`
	Entropy     float64  `toml:"entropy"`
	MinLen      int      `toml:"min_len"`
	MaxLen      int      `toml:"max_len"`
	Severity    string   `toml:"severity"`
	Tags        []string `toml:"tags"`
}

type AIConfig struct {
	// Mode: "on" (default — require a real verifier and fail if none can be
	// constructed), "auto" (use AI when credentials happen to be available,
	// otherwise degrade silently), "off" (heuristic verification only).
	//
	// The default is "on" because Klarion is an adjudicator with an entropy
	// pre-filter, not an entropy scanner with an optional AI feature. A missing
	// key is a misconfiguration, and "auto" turns it into a quiet downgrade to
	// output that flags identifiers, certificates and vendored code as secrets.
	// Failing loudly is the only honest default; "auto" remains available for
	// callers who genuinely want best-effort behaviour.
	Mode string `toml:"mode"`
	// Provider: "anthropic" (Messages API over plain net/http, no SDK),
	// "openai" (any OpenAI-compatible endpoint), "ollama" (alias for openai
	// with a localhost default URL) or "claude-cli" (shell out to a logged-in
	// Claude Code CLI; no API key).
	Provider string `toml:"provider"`
	// Model: default "claude-haiku-4-5" — fast, cheap classification.
	Model   string `toml:"model"`
	BaseURL string `toml:"base_url"`
	// APIKeyEnv names the environment variable holding the provider's API key.
	// Left empty it resolves per provider (anthropic → ANTHROPIC_API_KEY,
	// openai → OPENAI_API_KEY, ollama/claude-cli → none). It is deliberately
	// NOT defaulted here: a global default would hand, say, an Anthropic key
	// to whatever endpoint ai.provider happens to name.
	APIKeyEnv string `toml:"api_key_env"`
	// MaxBatch: findings adjudicated per model request.
	MaxBatch int `toml:"max_batch"`
	// MaxConcurrency: batches adjudicated in parallel. Raise it to scan large
	// repositories faster, lower it if the provider rate-limits you.
	MaxConcurrency int `toml:"max_concurrency"`
	TimeoutSecs    int `toml:"timeout_seconds"`
	// OnError: "keep" leaves findings unverified when the verifier errors
	// (fail-safe for a security tool); "fail" aborts the scan.
	OnError string `toml:"on_error"`
	// FilterFalsePositives: verdict=false_positive findings (with confidence
	// ≥ MinConfidence) are excluded from the failing set and demoted to the
	// suppressed list.
	FilterFalsePositives bool    `toml:"filter_false_positives"`
	MinConfidence        float64 `toml:"min_confidence"`
	// SendSecret: include the raw candidate in the verification request.
	// Set false for strict privacy (redacted form is sent; accuracy drops).
	SendSecret bool `toml:"send_secret"`
	// MaxContextLines caps the context snippet sent per finding.
	MaxContextLines int `toml:"max_context_lines"`
	// ReasoningEffort is forwarded to providers that expose it ("low",
	// "medium", "high"). Adjudication is classification, not deliberation: a
	// reasoning model left at its default spends most of the response budget
	// narrating why a string is or is not a secret, and those tokens are billed
	// and rate-limited like any other. Measured on Groq's openai/gpt-oss-20b,
	// reasoning traces dominated token use by roughly 3x. Empty leaves the
	// provider default alone, which is right for non-reasoning models.
	ReasoningEffort string `toml:"reasoning_effort"`
	// CachePath persists adjudicated verdicts between runs, keyed by a one-way
	// hash of (rule id, secret) and scoped to the provider+model. Empty
	// disables it. Only the status and confidence are stored — never the
	// secret, and never the model's written reason, which quotes the candidate.
	// Point CI at a cached/committed path to stop re-paying for unchanged code.
	CachePath string `toml:"cache_path"`
}

type ReportConfig struct {
	Format         string `toml:"format"` // text|json|sarif|junit|gitlab
	Redact         bool   `toml:"redact"`
	ShowSuppressed bool   `toml:"show_suppressed"`
}

type HookConfig struct {
	// FailOpen: internal scanner errors never block the agent/commit.
	FailOpen bool `toml:"fail_open"`
	// BlockOn: minimum severity that triggers a deny in hook mode.
	BlockOn string `toml:"block_on"`
	// Decision for Claude Code PreToolUse hits: "deny" or "ask".
	Decision string `toml:"decision"`
}

type BaselineConfig struct {
	Path string `toml:"path"`
}

// Default returns production defaults. Never construct Config directly.
func Default() *Config {
	c := &Config{
		Scan: ScanConfig{
			MaxFileSizeBytes: 1 << 20,
			MaxDecodeDepth:   2,
			IgnorePaths: []string{
				// Klarion's own state. Both files are full of hex digests
				// (verdict-cache keys, baseline fingerprints) which read as
				// high-entropy tokens — scanning them makes every run report
				// the previous run's bookkeeping as new secrets.
				".klarion/**", ".klarion-baseline.json",
				".git/**", "node_modules/**", "vendor/**", "dist/**", "build/**",
				// Bundled third-party source. next.js ships Babel under
				// packages/next/src/compiled/, which produced 150 of its 174
				// entropy false positives.
				"compiled/**", "third_party/**", "vendored/**",
				"target/**", ".venv/**", "__pycache__/**",
				"*.min.js", "*.min.css", "*.map", "*.lock", "package-lock.json",
				"yarn.lock", "pnpm-lock.yaml", "go.sum", "Cargo.lock",
				"*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.ico", "*.svg",
				// Encoded binary. A base64 blob is maximum entropy by
				// construction and never a credential -- symfony ships
				// favicon.png.base64, whose single line produced five
				// candidates that the model could only answer "uncertain",
				// and uncertain is kept. The image extensions above do not
				// match because the encoding extension comes last.
				"*.base64", "*.b64", "*.uu", "*.pem.txt",
				"*.pdf", "*.zip", "*.gz", "*.tar", "*.jar", "*.war", "*.7z",
				"*.woff", "*.woff2", "*.ttf", "*.eot", "*.otf",
				"*.mp3", "*.mp4", "*.mov", "*.avi", "*.wasm", "*.so", "*.dylib",
				"*.dll", "*.exe", "*.bin", "*.class", "*.pyc",
			},
		},
		Entropy: EntropyConfig{
			Enabled:            true,
			Alpha:              2.0,
			MinLength:          20,
			MaxLength:          512,
			Threshold:          0.88,
			ThresholdNoContext: 0.95,
			RequireDigit:       true,
		},
		AI: AIConfig{
			Mode:     "on",
			Provider: "anthropic",
			Model:    "claude-haiku-4-5",
			// APIKeyEnv intentionally unset — resolved per provider. See the
			// field comment on AIConfig.
			MaxBatch:             8,
			MaxConcurrency:       4,
			TimeoutSecs:          45,
			OnError:              "keep",
			FilterFalsePositives: true,
			MinConfidence:        0.6,
			SendSecret:           true,
			MaxContextLines:      3,
		},
		Report:   ReportConfig{Format: "text", Redact: true},
		Hook:     HookConfig{FailOpen: true, BlockOn: "low", Decision: "deny"},
		Baseline: BaselineConfig{Path: ".klarion-baseline.json"},
	}
	if err := c.compile(); err != nil {
		// Defaults contain no user input; a failure here is a programmer error.
		panic(err)
	}
	return c
}

// Load reads a TOML config file layered on top of Default().
func Load(path string) (*Config, error) {
	c := Default()
	meta, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if un := meta.Undecoded(); len(un) > 0 {
		keys := make([]string, 0, len(un))
		for _, k := range un {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	c.normalize()
	if err := c.compile(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// FindAndLoad locates configuration for dir: $KLARION_CONFIG wins, then
// .klarion.toml / klarion.toml walking up toward the filesystem root. When
// nothing is found the defaults are returned with an empty source path.
func FindAndLoad(dir string) (*Config, string, error) {
	if env := os.Getenv("KLARION_CONFIG"); env != "" {
		c, err := Load(env)
		return c, env, err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	for d := abs; ; d = filepath.Dir(d) {
		for _, name := range []string{".klarion.toml", "klarion.toml"} {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				c, err := Load(p)
				return c, p, err
			}
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	return Default(), "", nil
}

func (c *Config) normalize() {
	if c.Entropy.MinLength < 16 {
		c.Entropy.MinLength = 16
	}
	if c.Entropy.MaxLength <= c.Entropy.MinLength {
		c.Entropy.MaxLength = 512
	}
	if c.Entropy.Alpha <= 0 {
		c.Entropy.Alpha = 2.0
	}
	if c.Scan.MaxFileSizeBytes <= 0 {
		c.Scan.MaxFileSizeBytes = 1 << 20
	}
	c.Scan.MaxDecodeDepth = min(max(c.Scan.MaxDecodeDepth, 0), 5)
	if c.AI.MaxBatch <= 0 {
		c.AI.MaxBatch = 8
	}
	if c.AI.MaxConcurrency <= 0 {
		c.AI.MaxConcurrency = 4
	}
	if c.AI.TimeoutSecs <= 0 {
		c.AI.TimeoutSecs = 45
	}
	if c.AI.Provider == "ollama" && c.AI.BaseURL == "" {
		c.AI.BaseURL = "http://localhost:11434/v1"
	}
}

func (c *Config) compile() error {
	var err error
	if c.ignoreRes, err = compileGlobs(c.Scan.IgnorePaths); err != nil {
		return fmt.Errorf("scan.ignore_paths: %w", err)
	}
	if c.allowPathRes, err = compileGlobs(c.Allowlist.Paths); err != nil {
		return fmt.Errorf("allowlist.paths: %w", err)
	}
	c.allowSecretRes = c.allowSecretRes[:0]
	for _, p := range c.Allowlist.Regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("allowlist.regexes %q: %w", p, err)
		}
		c.allowSecretRes = append(c.allowSecretRes, re)
	}
	return nil
}

// PathIgnored reports whether a (repo-relative) path should not be scanned.
func (c *Config) PathIgnored(rel string) bool { return matchAny(c.ignoreRes, rel) }

// PathAllowlisted reports whether findings in this path are suppressed.
func (c *Config) PathAllowlisted(rel string) bool { return matchAny(c.allowPathRes, rel) }

// SecretAllowlisted reports whether the secret matches a user allowlist regex.
func (c *Config) SecretAllowlisted(secret string) bool {
	for _, re := range c.allowSecretRes {
		if re.MatchString(secret) {
			return true
		}
	}
	return false
}

// FingerprintAllowlisted reports whether fp is permanently allowlisted.
func (c *Config) FingerprintAllowlisted(fp string) bool {
	for _, f := range c.Allowlist.Fingerprints {
		if f == fp {
			return true
		}
	}
	return false
}

// Stopwords returns built-in placeholder markers merged with user additions.
// Matching is case-insensitive substring on the candidate secret.
func (c *Config) Stopwords() []string {
	return append(builtinStopwords(), c.Allowlist.Stopwords...)
}

func builtinStopwords() []string {
	return []string{
		"example", "sample", "dummy", "placeholder", "changeme", "change-me",
		"change_me", "your_", "your-", "<your", "yourkey", "insert_",
		"replaceme", "replace_me", "redacted", "xxxxxx", "test1234",
		"password123", "passw0rd", "secret123", "deadbeef", "not_a_real",
		"notreal", "fixme", "todo", "lorem", "ipsum", "abcdefgh", "12345678",
		"00000000", "fakekey", "fake_key", "fake-key", "spdx-license",
	}
}

// MatchGlob reports whether path matches a Klarion glob pattern.
// Supported syntax: `*` (any run within a segment), `?` (one char within a
// segment), `**` (any run across segments), `**/` (zero or more segments).
// A pattern without `/` matches against the basename; a pattern with `/`
// matches the slash-separated path or any of its segment-aligned suffixes
// (gitignore-like behavior).
func MatchGlob(pattern, path string) bool {
	re, err := regexp.Compile(globToRegex(pattern))
	if err != nil {
		return false
	}
	return matchOne(re, pattern, path)
}

func compileGlobs(patterns []string) ([]globMatcher, error) {
	res := make([]globMatcher, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(globToRegex(p))
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", p, err)
		}
		res = append(res, globMatcher{re: re, pattern: p})
	}
	return res, nil
}

func matchAny(ms []globMatcher, path string) bool {
	for _, m := range ms {
		if matchOne(m.re, m.pattern, path) {
			return true
		}
	}
	return false
}

func matchOne(re *regexp.Regexp, pattern, path string) bool {
	p := filepath.ToSlash(path)
	if !strings.Contains(pattern, "/") {
		return re.MatchString(filepath.Base(p))
	}
	// Match full path, then every segment-aligned suffix (gitignore-like).
	for {
		if re.MatchString(p) {
			return true
		}
		i := strings.Index(p, "/")
		if i < 0 {
			return false
		}
		p = p[i+1:]
	}
}

func globToRegex(pattern string) string {
	var b strings.Builder
	b.WriteString("^")
	p := filepath.ToSlash(pattern)
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				if i+2 < len(p) && p[i+2] == '/' {
					b.WriteString(`(?:[^/]*/)*`)
					i += 2
				} else {
					b.WriteString(`.*`)
					i++
				}
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			b.WriteString(`[^/]`)
		case '.', '+', '(', ')', '|', '[', ']', '{', '}', '^', '$', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	return b.String()
}
