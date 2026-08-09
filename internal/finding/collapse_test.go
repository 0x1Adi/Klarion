package finding

import "testing"

func TestIsTestPath(t *testing.T) {
	// The false-negative class that matters: a directory whose name merely
	// ends in "test" is not a test tree. Getting this wrong silently marks
	// production code as fixtures.
	notTests := []string{
		"src/latest/config.go",
		"pkg/contest/handler.go",
		"internal/protest/main.go",
		"app/attestation/signer.go",
		"cmd/server/main.go",
		"src/main/resources/application.yml",
	}
	for _, p := range notTests {
		if IsTestPath(p) {
			t.Errorf("IsTestPath(%q) = true, want false", p)
		}
	}

	tests := []string{
		"module/spring-boot-mail/src/dockerTest/resources/ssl/test-client.key",
		"integration-test/sni/src/main/resources/test-hello-server.key",
		"smoke-test/data-redis/src/test/resources/ssl/client.key",
		"internal/backend/remote-state/http/testdata/certs/client.key",
		"src/Symfony/Component/Mime/Tests/Crypto/DkimSignerTest.php",
		"packages/next/test/e2e/custom-server/ssh/ca-key.pem",
		"app/__tests__/auth.spec.ts",
		"examples/with-sentry/README.md",
		"internal/lang/funcs/crypto_test.go",
	}
	for _, p := range tests {
		if !IsTestPath(p) {
			t.Errorf("IsTestPath(%q) = false, want true", p)
		}
	}
}

func TestIsKeyMaterialPath(t *testing.T) {
	yes := []string{
		"a/b/client.key", "certs/ca.pem", "ssl/server.crt", "x/keystore.jks",
		"home/.ssh/id_rsa", "home/.ssh/id_ed25519", "saml/privatekey.txt",
		"autoconfigure/private-key-location",
	}
	for _, p := range yes {
		if !IsKeyMaterialPath(p) {
			t.Errorf("IsKeyMaterialPath(%q) = false, want true", p)
		}
	}
	no := []string{"main.go", ".env", "config/keys.yml", "monkey.json", "turkey.md"}
	for _, p := range no {
		if IsKeyMaterialPath(p) {
			t.Errorf("IsKeyMaterialPath(%q) = true, want false", p)
		}
	}
}

func mk(file, rule string, lines ...int) []Finding {
	out := make([]Finding, 0, len(lines))
	for _, l := range lines {
		out = append(out, Finding{FilePath: file, RuleID: rule, Line: l})
	}
	return out
}

func TestCollapseKeyBlocks(t *testing.T) {
	// A wrapped PEM body: 19 consecutive lines, one credential.
	in := mk("certs/client.key", "generic-high-entropy",
		2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
	got := CollapseKeyBlocks(in)
	if len(got) != 1 {
		t.Fatalf("PEM block: got %d findings, want 1", len(got))
	}
	if got[0].Line != 2 {
		t.Errorf("collapsed finding anchored at line %d, want 2", got[0].Line)
	}
	if got[0].Occurrences != 19 {
		t.Errorf("Occurrences = %d, want 19", got[0].Occurrences)
	}

	// A key embedded as a string literal in test source: not a key-material
	// path, so eligibility comes from the armor in the context window.
	armor := "-----BEGIN RSA PRIVATE KEY-----"
	inline := mk("internal/lang/funcs/crypto_test.go", "generic-high-entropy", 30, 31, 32, 33, 34, 35)
	inline[0].Context = armor
	if got := CollapseKeyBlocks(inline); len(got) != 1 || got[0].Occurrences != 6 {
		t.Errorf("inline PEM: got %d findings (occ=%d), want 1 (occ=6)", len(got), got[0].Occurrences)
	}

	// Same shape with no armor anywhere must NOT collapse -- six consecutive
	// high-entropy lines in ordinary source could be six distinct secrets.
	plainRun := mk("internal/config/keys.go", "generic-high-entropy", 30, 31, 32, 33, 34, 35)
	if got := CollapseKeyBlocks(plainRun); len(got) != 6 {
		t.Errorf("unarmored run: got %d findings, want 6 (must not collapse)", len(got))
	}

	// FALSE-NEGATIVE GUARD. Three distinct secrets on consecutive lines of a
	// .env must never be collapsed -- that would hide two real leaks. It is
	// neither a key-material path nor an armored file, so it is not eligible.
	env := mk(".env", "generic-high-entropy", 1, 2, 3, 4, 5)
	if got := CollapseKeyBlocks(env); len(got) != 5 {
		t.Errorf(".env: got %d findings, want 5 (must not collapse)", len(got))
	}

	// Two adjacent findings are below minRun: a keypair file holding a short
	// key and its passphrase should keep both.
	pair := mk("certs/client.key", "generic-high-entropy", 4, 5)
	if got := CollapseKeyBlocks(pair); len(got) != 2 {
		t.Errorf("2-line run: got %d findings, want 2", len(got))
	}

	// Different rules in the same file are independent blocks.
	mixed := append(mk("certs/a.pem", "rule-a", 1, 2, 3), mk("certs/a.pem", "rule-b", 10, 11, 12)...)
	if got := CollapseKeyBlocks(mixed); len(got) != 2 {
		t.Errorf("two rules: got %d findings, want 2", len(got))
	}

	// A gap larger than maxGap starts a new block.
	split := mk("certs/a.pem", "r", 1, 2, 3, 40, 41, 42)
	if got := CollapseKeyBlocks(split); len(got) != 2 {
		t.Errorf("split blocks: got %d findings, want 2", len(got))
	}

	// Nothing eligible: input returned untouched.
	plain := mk("main.go", "r", 1, 2, 3)
	if got := CollapseKeyBlocks(plain); len(got) != 3 {
		t.Errorf("non-key file: got %d findings, want 3", len(got))
	}
}
