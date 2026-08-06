package rules

// The fixture credentials in this file are synthetic and non-functional, but
// they are deliberately written in real issuer formats — that is the whole
// point of testing a secret detector. Each one is split across a concatenation
// ("ghp_" + "ab12...") so that upstream secret scanners and GitHub push
// protection cannot match them as contiguous text. Go folds the parts at
// compile time, so every assertion still sees the fully assembled string.
// Do not join them back together: doing so makes this repo unpushable.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// kebab matches lowercase kebab-case identifiers: alnum groups joined by '-'.
var kebab = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// TestBuiltinInvariants enforces the structural contract every rule must obey:
// unique kebab-case IDs, compiled regexes, lowercase keywords, a SecretGroup
// that actually exists in the regex, and a real severity.
func TestBuiltinInvariants(t *testing.T) {
	rules := Builtin()
	if len(rules) < 50 {
		t.Fatalf("expected the curated set to have >=50 rules, got %d", len(rules))
	}

	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if r.ID == "" {
			t.Errorf("rule with empty ID: %+v", r)
			continue
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		seen[r.ID] = true

		if !kebab.MatchString(r.ID) {
			t.Errorf("rule ID %q is not kebab-case", r.ID)
		}
		if r.Description == "" {
			t.Errorf("rule %q has no description", r.ID)
		}
		if r.Regex == nil {
			t.Errorf("rule %q has nil regex", r.ID)
			continue
		}
		// SecretGroup must be addressable: 0 (whole match) up to NumSubexp.
		if r.SecretGroup < 0 || r.SecretGroup > r.Regex.NumSubexp() {
			t.Errorf("rule %q SecretGroup %d out of range (regex has %d groups)",
				r.ID, r.SecretGroup, r.Regex.NumSubexp())
		}
		for _, kw := range r.Keywords {
			if kw != strings.ToLower(kw) {
				t.Errorf("rule %q keyword %q is not lowercase", r.ID, kw)
			}
			if kw == "" {
				t.Errorf("rule %q has an empty keyword", r.ID)
			}
		}
		switch r.Severity {
		case finding.SeverityCritical, finding.SeverityHigh,
			finding.SeverityMedium, finding.SeverityLow:
		default:
			t.Errorf("rule %q has invalid severity %q", r.ID, r.Severity)
		}
		if r.Entropy < 0 || r.Entropy > 1 {
			t.Errorf("rule %q entropy floor %f outside [0,1]", r.ID, r.Entropy)
		}
	}
}

// byID indexes the ruleset for the fixture-driven tests below.
func byID(t *testing.T) map[string]Rule {
	t.Helper()
	m := make(map[string]Rule)
	for _, r := range Builtin() {
		m[r.ID] = r
	}
	return m
}

// fixtures pairs each covered rule with a positive line that must match (and
// whose SecretGroup must equal want) and a negative line that must NOT match.
// All secrets here are fabricated.
var fixtures = []struct {
	id   string
	pos  string
	want string // expected captured secret (SecretGroup)
	neg  string
}{
	{
		id:   "aws-access-key-id",
		pos:  `aws_access_key_id = ` + `AKIAZ9Q7RT4XK2LMN8PQ`,
		want: `AKIAZ9Q7RT` + `4XK2LMN8PQ`,
		neg:  `just a token AKIA123 nope`,
	},
	{
		id:   "gcp-api-key",
		pos:  `key: AIzaS` + `yD3kL9mNpQrStUvWxYz0123456789AbCdE`,
		want: `AIzaS` + `yD3kL9mNpQrStUvWxYz0123456789AbCdE`,
		neg:  `AIza_too_short`,
	},
	{
		id:   "gcp-oauth-client-secret",
		pos:  `client_secret=GOCSPX-abc` + `dEFGH1234ijklMNOP5678qrst`,
		want: `GOCSPX-abcdEFGH12` + `34ijklMNOP5678qrst`,
		neg:  `GOCSPX-short`,
	},
	{
		id:   "github-pat",
		pos:  `token = ghp_` + `A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`,
		want: `ghp_` + `A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`,
		neg:  `ghp_short`,
	},
	{
		id:   "github-fine-grained-pat",
		pos:  `github_pat_11ABCDE0123456789_abcdefghijklmnopq` + `rstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB`,
		want: `github_pat_11ABCDE0123456789_abcdefghijklmnopq` + `rstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB`,
		neg:  `github_pat_tooshort`,
	},
	{
		id:   "gitlab-pat",
		pos:  `GITLAB_TOKEN=glpat-` + `abcABC1234567890_-xy`,
		want: `glpat-` + `abcABC1234567890_-xy`,
		neg:  `glpat-short`,
	},
	{
		id:   "slack-token",
		pos:  `SLACK=xoxb-1234567890-` + `0987654321-abcdefghijklmnopqrstuvwx`,
		want: `xoxb-1234567890-` + `0987654321-abcdefghijklmnopqrstuvwx`,
		neg:  `xoxz-not-a-real-prefix`,
	},
	{
		id:   "slack-webhook-url",
		pos:  `url=https://hooks.slack.com/services/T00000000/B11111111/` + `abcdefghijklmnopqrstuvwx`,
		want: `https://hooks.slack.com/services/T00000000/B11111111/` + `abcdefghijklmnopqrstuvwx`,
		neg:  `https://hooks.slack.com/services/incomplete`,
	},
	{
		id:   "stripe-secret-key",
		pos:  `STRIPE=sk_` + `live_4eC39HqLyjWDarjtT1zdp7dc`,
		want: `sk_` + `live_4eC39HqLyjWDarjtT1zdp7dc`,
		neg:  `sk_live_short`,
	},
	{
		id:   "stripe-publishable-key",
		pos:  `pk = pk_live_51H8sT2eZ` + `vKYlo2Cabcdefghijklmnop`,
		want: `pk_live_51H8sT2eZvKY` + `lo2Cabcdefghijklmnop`,
		neg:  `pk_live_x`,
	},
	{
		id:   "anthropic-api-key",
		pos:  `ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdefghijklmnopqrstuv` + `wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvw`,
		want: `sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyzABCDE` + `FGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvw`,
		neg:  `sk-ant-api03-short`,
	},
	{
		id:   "openai-api-key",
		pos:  `OPENAI_API_KEY=sk-0123456789abcde` + `fghijklmnopqrstuvwxyzABCDEFGHIJKL`,
		want: `sk-0123456789abcdefghijkl` + `mnopqrstuvwxyzABCDEFGHIJKL`,
		neg:  `sk-ant-api03-abcdef`, // hyphenated form must not be caught here
	},
	{
		id:   "huggingface-token",
		pos:  `HF_TOKEN=hf_0123456789a` + `bcdefghijklmnopqrstuvwx`,
		want: `hf_0123456789abcde` + `fghijklmnopqrstuvwx`,
		neg:  `hf_short`,
	},
	{
		id:   "groq-api-key",
		pos:  `GROQ=gsk_0123456789abcdefghijk` + `lmnopqrstuvwxyzABCDEFGHIJKLMNOP`,
		want: `gsk_0123456789abcdefghijklmn` + `opqrstuvwxyzABCDEFGHIJKLMNOP`,
		neg:  `gsk_short`,
	},
	{
		id:   "sendgrid-api-key",
		pos:  `SENDGRID=SG.abcdefghijklmnopqrstuv.0123` + `456789abcdefghijklmnopqrstuvwxyz0123456`,
		want: `SG.abcdefghijklmnopqrstuv.01234567` + `89abcdefghijklmnopqrstuvwxyz0123456`,
		neg:  `SG.too.short`,
	},
	{
		id:   "postgres-connection-uri",
		pos:  `DATABASE_URL=postgres://admin:s` + `up3rs3cr3t@db.internal:5432/app`,
		want: `postgres://admin:sup3r` + `s3cr3t@db.internal:5432`,
		neg:  `postgres://localhost:5432/app`, // no credentials
	},
	{
		id:   "jwt",
		pos:  `Authorization stored eyJhb` + `GciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
		want: `eyJhb` + `GciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
		neg:  `eyJonly.onesegment`,
	},
	{
		id:   "private-key",
		pos:  `-----BEGIN RSA ` + `PRIVATE KEY-----`,
		want: `-----BEGIN RSA ` + `PRIVATE KEY-----`,
		neg:  `-----BEGIN CERTIFICATE-----`,
	},
	{
		id:   "npm-token",
		pos:  `//registry.npmjs.org/:_authToken=npm_` + `A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`,
		want: `npm_` + `A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8`,
		neg:  `npm_short`,
	},
	{
		id:   "digitalocean-token",
		pos:  `DO_TOKEN=dop_v1_` + `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`,
		want: `dop_v1_` + `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`,
		neg:  `dop_v1_short`,
	},
	{
		id:   "shopify-access-token",
		pos:  `SHOPIFY=shpat_0123456789` + `abcdef0123456789abcdef`,
		want: `shpat_0123456789` + `abcdef0123456789abcdef`,
		neg:  `shpat_short`,
	},
	{
		id:   "linear-api-key",
		pos:  `LINEAR=lin_api_0123456789ab` + `cdefghijklmnopqrstuvwxyz0123`,
		want: `lin_api_0123456789abcdef` + `ghijklmnopqrstuvwxyz0123`,
		neg:  `lin_api_short`,
	},
	{
		id:   "discord-webhook-url",
		pos:  `hook=https://discord.com/api/webhooks/123456789012345678/abcde` + `fghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef`,
		want: `https://discord.com/api/webhooks/123456789012345678/abcdefgh` + `ijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef`,
		neg:  `https://discord.com/api/webhooks/incomplete`,
	},
	{
		id:   "vault-token",
		pos:  `VAULT_TOKEN=hvs.CAESIabcde` + `fghijklmnopqrstuvwxyz012345`,
		want: `hvs.CAESIabcdefghijk` + `lmnopqrstuvwxyz012345`,
		neg:  `hvs.short`,
	},
}

// TestFixturesMatch verifies each covered rule matches its positive fixture
// (capturing the exact secret at SecretGroup) and rejects its negative fixture.
func TestFixturesMatch(t *testing.T) {
	rules := byID(t)
	for _, f := range fixtures {
		f := f
		t.Run(f.id, func(t *testing.T) {
			r, ok := rules[f.id]
			if !ok {
				t.Fatalf("fixture references unknown rule %q", f.id)
			}

			m := r.Regex.FindStringSubmatch(f.pos)
			if m == nil {
				t.Fatalf("rule %q did not match positive fixture %q", f.id, f.pos)
			}
			got := m[0]
			if r.SecretGroup > 0 {
				if r.SecretGroup >= len(m) {
					t.Fatalf("rule %q SecretGroup %d exceeds submatch count %d",
						f.id, r.SecretGroup, len(m))
				}
				got = m[r.SecretGroup]
			}
			if got != f.want {
				t.Errorf("rule %q captured %q, want %q", f.id, got, f.want)
			}

			if r.Regex.MatchString(f.neg) {
				t.Errorf("rule %q wrongly matched negative fixture %q", f.id, f.neg)
			}
		})
	}
}

// TestFixtureKeywordsFire proves the cheap keyword prescreen won't skip a real
// hit: at least one of the rule's keywords appears (lowercased) in every
// positive fixture. A rule with no keywords always runs, so it trivially passes.
func TestFixtureKeywordsFire(t *testing.T) {
	rules := byID(t)
	for _, f := range fixtures {
		r := rules[f.id]
		if len(r.Keywords) == 0 {
			continue
		}
		low := strings.ToLower(f.pos)
		found := false
		for _, kw := range r.Keywords {
			if strings.Contains(low, kw) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %q: no keyword %v found in fixture %q; prescreen would skip it",
				f.id, r.Keywords, f.pos)
		}
	}
}
