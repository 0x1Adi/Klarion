package verify

import (
	"fmt"
	"testing"
)

// req builds a Request whose context contains the matched line in the same
// "<n>: <text>" shape the detector emits.
func req(ruleID, secret, line string) Request {
	return Request{
		RuleID:   ruleID,
		Line:     10,
		Secret:   secret,
		Context:  fmt.Sprintf("9: before\n10: %s\n11: after", line),
		FilePath: "app/models/user.rb",
	}
}

// TestStructuralFPSuppresses covers the false-positive classes that dominated
// the no-AI run over the rails/flask corpora. Each case is a real line from
// those repositories.
func TestStructuralFPSuppresses(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		secret  string
		line    string
		generic bool
	}{
		{"rdoc markup", "generic-high-entropy", "password_confirmation",
			"# The added +password_confirmation+ attribute is virtual", true},
		{"comment line", "generic-high-entropy", "10f2163b45388899ad4d5ae9489882",
			`#   <input name="authenticity_token" value="10f2163b45388899ad4d5ae9489882">`, true},
		{"unquoted call", "generic-secret-assignment", "ActiveStorage.verifier.verified",
			"token = ActiveStorage.verifier.verified(params[:encoded_token])", true},
		{"snake_case local", "generic-secret-assignment", "generate_connection_token",
			"@connection_token = generate_connection_token", true},
		{"leading underscore key", "generic-secret-assignment", "_aj_hash_with_indifferent_access",
			`WITH_INDIFFERENT_ACCESS_KEY = "_aj_hash_with_indifferent_access"`, true},
		{"ruby symbol", "generic-password-assignment", ":BCryptPassword",
			"register_algorithm :bcrypt, SecurePassword::BCryptPassword", true},
		{"method definition", "generic-high-entropy", "ignore_default_scope",
			"def ignore_default_scope=(ignore)", true},
		{"uint64 sentinel", "generic-high-entropy", "18446744073709551615",
			"o.limit = Arel::Nodes::Limit.new(18446744073709551615)", true},
		{"md5 self-test vector", "generic-high-entropy", "5d41402abc4b2a76b9719d911017c592",
			`if (hex(md51("hello")) !== "5d41402abc4b2a76b9719d911017c592") ;`, true},
		{"string interpolation", "generic-password-assignment", "#{mysql_config[:password]}",
			`args << "--password=#{mysql_config[:password]}"`, true},
		{"cli flag", "generic-password-assignment", "--password",
			`password:  "--password",`, true},
		// Placeholder rules apply to pattern rules too, not just generic ones.
		{"placeholder password", "generic-password-assignment", "postgres",
			"POSTGRES_PASSWORD: postgres", false},
		{"placeholder dsn", "postgres-connection-uri", "postgres://postgres:postgres@localhost:5432",
			"DATABASE_URL: postgres://postgres:postgres@localhost:5432", false},
		{"documented dsn", "postgres-connection-uri", "postgresql://foo:bar@localhost:9000",
			`#   url = "postgresql://foo:bar@localhost:9000/foo_test"`, false},
	}
	docs := Request{
		RuleID: "generic-high-entropy", Line: 10,
		Secret:   "5f352379324c22463451387a0aec5d2f",
		Context:  "10: $ export FLASK_SECRET_KEY=\"5f352379324c22463451387a0aec5d2f\"",
		FilePath: "docs/config.rst",
	}
	if structuralFP(docs, true) == "" {
		t.Error("entropy-only match in docs/config.rst should be suppressed")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := structuralFP(req(c.ruleID, c.secret, c.line), c.generic); got == "" {
				t.Errorf("structuralFP(%q) = \"\", want a suppression reason", c.secret)
			}
		})
	}
}

// TestStructuralFPPreservesRecall is the important half: these are real leaked
// credentials from the leaky-repo corpus. A suppressor that fires here is a
// silent recall regression, which on a security tool is far worse than noise.
func TestStructuralFPPreservesRecall(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		secret  string
		line    string
		generic bool
	}{
		// PEM bodies are unquoted, contain '+' pairs, and can start with "//".
		{"pem body", "generic-high-entropy", "Vlg8TPplRMEZCk4IpswUk+8IMSmn+ci3+wJaoaNcxwr5IratyIvKuypOCKxZvlfD",
			"Vlg8TPplRMEZCk4IpswUk+8IMSmn+ci3+wJaoaNcxwr5IratyIvKuypOCKxZvlfD", true},
		{"pem body with plus markup shape", "generic-high-entropy", "+SY+Yv0J0ObZThBKfEgTnoliiJi0pxpNMqg4cA5HCe",
			"+SY+Yv0J0ObZThBKfEgTnoliiJi0pxpNMqg4cA5HCe/hZxoQONVLtrUfJ7H8KDfL", true},
		{"pem body starting with slashes", "generic-high-entropy", "//8IMSmnciwJaoaNcxwr5IratyIvKuypOCKxZvlfD",
			"//8IMSmnciwJaoaNcxwr5IratyIvKuypOCKxZvlfD", true},
		{"ssh public key", "generic-high-entropy", "AAAAB3NzaC1yc2EAAAADAQABAAABAQCOiwy0NSpsTX",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCOiwy0NSpsTX user@host", true},
		// Unquoted values in dotenv / passwd-style files are real secrets.
		{"dotenv value", "generic-password-assignment", "s3cr3tp4ssw0rd",
			"DB_PASSWORD=s3cr3tp4ssw0rd", true},
		{"shadow hash", "generic-high-entropy", "$6$rounds=656000$YQjLpLQwq$Xk9",
			"root:$6$rounds=656000$YQjLpLQwq$Xk9:18000:0:99999:7:::", true},
		{"rails master key", "generic-high-entropy", "3b7cd72c9a1e4f8b2d6a0e5c1f9b8a47",
			"3b7cd72c9a1e4f8b2d6a0e5c1f9b8a47", true},
		// A real credential inside a DSN must survive the placeholder rule.
		{"real dsn", "postgres-connection-uri", "postgres://admin:Xk9vQ2mRt7LpZw@db.prod.internal:5432",
			"DATABASE_URL=postgres://admin:Xk9vQ2mRt7LpZw@db.prod.internal:5432", false},
		// Provider-pattern matches are never shape-suppressed, even in comments.
		{"aws key in comment", "aws-access-key-id", "AKIAIOSFODNN7EXAMPLE",
			"# AKIAIOSFODNN7EXAMPLE", false},
	}
	// A .txt dump is not documentation: leaky-repo's high-entropy-misc.txt holds
	// real credential material and must never be suppressed by the docs rule.
	if isDocFile("high-entropy-misc.txt") {
		t.Error("isDocFile must not treat .txt as documentation")
	}
	// A provider-pattern hit inside a doc file is still a real leak.
	pat := Request{
		RuleID: "aws-access-key-id", Line: 1, Secret: "AKIAIOSFODNN7EXAMPLE",
		Context: "1: key = AKIAIOSFODNN7EXAMPLE", FilePath: "docs/setup.rst",
	}
	if got := structuralFP(pat, false); got != "" {
		t.Errorf("provider match in docs suppressed: %s", got)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := structuralFP(req(c.ruleID, c.secret, c.line), c.generic); got != "" {
				t.Errorf("structuralFP(%q) suppressed real credential: %s", c.secret, got)
			}
		})
	}
}

// TestCapContextKeepsMatchedLine guards the centering fix: a head slice used to
// drop the very line the candidate was found on.
func TestCapContextKeepsMatchedLine(t *testing.T) {
	ctx := "7: a\n8: b\n9: c\n10: MATCH\n11: e\n12: f\n13: g"
	got := capContext(ctx, 3, 10)
	if want := "9: c\n10: MATCH\n11: e"; got != want {
		t.Errorf("capContext() = %q, want %q", got, want)
	}
	// A match at the top of a file must still be included.
	if got := capContext("1: MATCH\n2: b\n3: c\n4: d", 3, 1); got != "1: MATCH\n2: b\n3: c" {
		t.Errorf("capContext() at file start = %q", got)
	}
	// Unknown line number falls back to the head slice without panicking.
	if got := capContext(ctx, 3, 999); got != "7: a\n8: b\n9: c" {
		t.Errorf("capContext() unknown line = %q", got)
	}
}

func TestSecretIsQuoted(t *testing.T) {
	cases := []struct {
		line, secret string
		want         bool
	}{
		{`password = "hunter2"`, "hunter2", true},
		{`password = 'hunter2'`, "hunter2", true},
		{`password = other_password`, "other_password", false},
		{`token = generate(x)`, "generate(x)", false},
		{`DB_PASSWORD=s3cret`, "s3cret", false},
		// Unlocatable or empty input must be treated as quoted (no suppression).
		{`password = "hunter2"`, "nowhere", true},
		{``, "hunter2", true},
	}
	for _, c := range cases {
		if got := secretIsQuoted(c.line, c.secret); got != c.want {
			t.Errorf("secretIsQuoted(%q, %q) = %v, want %v", c.line, c.secret, got, c.want)
		}
	}
}
