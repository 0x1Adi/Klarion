package detect

// Fixtures here are generic passwords and made-up values in the shapes real
// credential files use (netrc, pgpass, FileZilla, wp-config). None is a
// provider token format.

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

func findSecret(fs []finding.Finding, secret string) *finding.Finding {
	for i := range fs {
		if fs[i].Secret == secret {
			return &fs[i]
		}
	}
	return nil
}

// Every case here was a real miss: an entropy floor, a stopword substring, a
// missing separator or a missing key name dropped it before the model saw it.
func TestStructuralFindsLowEntropyCredentials(t *testing.T) {
	d := newDet(t)
	cases := []struct {
		name, path, src, rule, secret string
	}{
		{"netrc pairs", ".netrc", "machine imap.example.com login me@example.com password pass123\n", idPassword, "pass123"},
		{"esmtprc quoted pair", ".esmtprc", "username \"me@example.com\"\npassword \"password\"\n", idPassword, "password"},
		{"pgpass by file name", "db/.pgpass", "#hostname:port:database:username:password\nlocalhost:5432:app:root:s3cret\n", idCredentialFile, "localhost:5432:app:root:s3cret"},
		{"htpasswd by file name", "public/.htpasswd", "admin:$apr1$tp8glkbm$fjg65tI1eipoBh62aEjIy0\n", "", "admin:$apr1$tp8glkbm$fjg65tI1eipoBh62aEjIy0"},
		{"git-credentials url", ".git-credentials", "https://user@example.com:pass!#@498@github.com\n", idURLCredentials, "pass!#@498"},
		{"xml element", "filezilla.xml", "  <User>root</User>\n  <Pass>ExamplePas123</Pass>\n", idPassword, "ExamplePas123"},
		{"xml attribute low entropy", ".idea/WebServers.xml", `<fileTransfer host="example.com" password="dff9dfdfdfdadfcf" username="root">` + "\n", idPassword, "dff9dfdfdfdadfcf"},
		{"stopword inside value", "ventrilo_srv.ini", "Password=UserPassword123\n", idPassword, "UserPassword123"},
		{"repeat run inside value", "logins.json", `"encryptedPassword": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYI",` + "\n", idPassword, "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYI"},
		{"bare pass key", ".ftpconfig", `"pass": "hunter22",` + "\n", idPassword, "hunter22"},
		{"passphrase key", ".ftpconfig", `"passphrase": "swordfish",` + "\n", idPassword, "swordfish"},
		{"_PASS suffix", "config", "IRC_PASS=irc_pass\n", idPassword, "irc_pass"},
		{"php define", "wp-config.php", "define( 'DB_PASSWORD', 'admin' );\n", idPassword, "admin"},
		{"php variable short value", "config.php", "$dbpasswd = 'pass123';\n", idPassword, "pass123"},
		{"secret key with punctuation", "settings.py", "SECRET_KEY = 'zh!=!gq(w^_t[sBR29954x)HI+$ehwss'\n", idSecret, "zh!=!gq(w^_t[sBR29954x)HI+$ehwss"},
		{"weak key, secret-shaped value", "wp-config.php", "define('LOGGED_IN_KEY', 'Q$:B]zZjN-AdT<>h7V1.vm+k^|}2wVZf');\n", idSecret, "Q$:B]zZjN-AdT<>h7V1.vm+k^|}2wVZf"},
		{"login call", "salesforce.js", "conn.login('user@example.com', 'salesforcepassword', function(err) {\n", idPassword, "salesforcepassword"},
		{"password comparison", "auth.py", "if password == \"hunter2x\":\n", idPassword, "hunter2x"},
		{"url credentials in config", "deploy.yml", "remote: https://deploy:Tr0ub4dor@git.example.com/app.git\n", idURLCredentials, "Tr0ub4dor"},
		{"url-encoded url password", "deploy.yml", "remote: https://deploy:p%40ss%3Aw0rd@git.example.com/app.git\n", idURLCredentials, "p%40ss%3Aw0rd"},
		{"commented-out credential", "app.go", "// password := \"letmein42\"\n", idPassword, "letmein42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := d.ScanContent(c.path, []byte(c.src))
			f := findSecret(fs, c.secret)
			if f == nil {
				t.Fatalf("missed %q; got %v %v", c.secret, ruleIDs(fs), secrets(fs))
			}
			if c.rule != "" && f.RuleID != c.rule {
				t.Errorf("rule = %s, want %s", f.RuleID, c.rule)
			}
		})
	}
}

// The other half: shapes that name a credential without holding one. Each of
// these produced candidates on real source trees while the stage was tuned.
func TestStructuralIgnoresNonValues(t *testing.T) {
	d := newDet(t)
	cases := []struct{ name, path, src string }{
		{"code expression", "app.py", "password = get_password(user)\n"},
		{"type annotation", "user.ts", "  password: string;\n"},
		{"template", "config.yml", "password: ${DB_PASSWORD}\n"},
		{"env reference", "run.sh", "PASSWORD=$DB_PASSWORD\n"},
		{"placeholder", "config.yml", "password: changeme\n"},
		{"masked", "config.yml", "password: \"********\"\n"},
		{"describes a password", "form.json", `"passwordField": "password",` + "\n"},
		{"timestamp of a password", "logins.json", `"timePasswordChanged": 1515902314887,` + "\n"},
		{"boolean", ".ftpconfig", `"promptForPass": false,` + "\n"},
		{"test status", "run.test", "--- PASS: TestIndex (0.00s)\n"},
		{"dotted constant key", "expr.go", "\ttoken.XOR: \"bitwise complement\",\n"},
		{"list items", "bench.py", "cmd = ['detect-secrets', 'scan']\n"},
		{"call on a symbol", "tokenize.py", "TokenInfo = namedtuple('TokenInfo', 'type string start end line')\n"},
		{"lexer comparison", "lexer.py", "if token == \"lambda\":\n"},
		{"prose", "Opticks.txt", "the Glass pass through a small round hole, or aperture made in\n"},
		{"weak key identifier value", "gen.go", "\t\"EncapsulationKeySize768\": \"EncapsulationKeySize1024\",\n"},
		{"weak key word value", "cache.py", "cache_key = \"user:profile:123\"\n"},
		{"url without credentials", ".npmrc", "registry=https://registry.npmjs.org:443/@scope/pkg\n"},
		{"cgo include is not xml", "lookup.go", "#include <pwd.h>\n#include <grp.h>\n"},
		{"empty env value then next key", ".env", "DB_PASSWORD=\nDB_HOST=localhost\n"},
		{"printf format", "log.py", "token_range = \"%d,%d-%d,%d:\"\n"},
		{"docstring value", "topics.py", "'pass': 'The \"pass\" statement\\n\\npass_stmt ::= \"pass\" and more words here',\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, f := range d.ScanContent(c.path, []byte(c.src)) {
				if f.RuleID != "generic-high-entropy" {
					t.Errorf("unexpected %s %q", f.RuleID, f.Secret)
				}
			}
		})
	}
}

func TestCredentialFileByName(t *testing.T) {
	yes := []string{".pgpass", "db/.pgpass", ".git-credentials", ".htpasswd", "proftpdpasswd", "secrets.yml", "passwords.txt", "client_secret_123.apps.example.com.json"}
	no := []string{"password_reset.rb", "tokenizer.json", "compass.json", "README.md", "password_policy.json", ".netrc"}
	for _, p := range yes {
		if !credentialFile(p) {
			t.Errorf("credentialFile(%q) = false", p)
		}
	}
	for _, p := range no {
		if credentialFile(p) {
			t.Errorf("credentialFile(%q) = true", p)
		}
	}
	// A name-derived file still needs credential-shaped lines: CSV bookkeeping
	// in secrets.csv is not a record.
	d := newDet(t)
	if fs := d.ScanContent("meta/secrets.csv", []byte(".bash_profile,6,5\ncloud/.s3cfg,1,2\n")); len(fs) != 0 {
		t.Errorf("csv rows flagged: %v", secrets(fs))
	}
}

func TestSplitKey(t *testing.T) {
	cases := map[string]string{
		"AdminPassword": "admin password", "IRC_PASS": "irc pass", "APIKey": "api key",
		"encryptedPassword": "encrypted password", "_authToken": "auth token",
		"$dbpasswd": "dbpasswd", "LOGGED_IN_KEY": "logged in key", "db.password": "db password",
	}
	for in, want := range cases {
		if got := strings.Join(splitKey(in), " "); got != want {
			t.Errorf("splitKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMultiLineValues(t *testing.T) {
	d := newDet(t)
	cases := []struct{ name, path, src, secret string }{
		{"yaml block scalar", "values.yml", "db:\n  password: |\n    Xk9mLp2qRt\n  host: db\n", "Xk9mLp2qRt"},
		{"split xml element", "settings.xml", "<password>\n  Xk9mLp2qRt\n</password>\n", "Xk9mLp2qRt"},
		{"quoted value on next line", "app.js", "const password =\n  \"Xk9mLp2qRt\";\n", "Xk9mLp2qRt"},
		{"deeper-indented plain value", "values.yml", "password:\n    Xk9mLp2qRt\n", "Xk9mLp2qRt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := d.ScanContent(c.path, []byte(c.src))
			f := findSecret(fs, c.secret)
			if f == nil {
				t.Fatalf("missed multi-line value; got %v %v", ruleIDs(fs), secrets(fs))
			}
			if !strings.Contains(f.LineText, c.secret) {
				t.Errorf("finding points at line %d (%q), not the value line", f.Line, f.LineText)
			}
			if len(fs) != 1 {
				t.Errorf("value reported %d times: %v", len(fs), ruleIDs(fs))
			}
		})
	}
}

func TestRelatedPartsReachTheVerifier(t *testing.T) {
	d := newDet(t)
	src := "<Server>\n  <Host>ftp.example.com</Host>\n  <Port>21</Port>\n  <User>root</User>\n  <Pass>ExamplePas123</Pass>\n</Server>\n"
	f := findSecret(d.ScanContent("filezilla.xml", []byte(src)), "ExamplePas123")
	if f == nil {
		t.Fatal("password not found")
	}
	for _, want := range []string{"User=root (line 4)", "Host=ftp.example.com (line 2)"} {
		if !strings.Contains(f.Related, want) {
			t.Errorf("related = %q, missing %q", f.Related, want)
		}
	}
	if strings.Contains(f.Related, "Port") {
		t.Errorf("related should carry identity fields only: %q", f.Related)
	}
}

func TestDecodeAndRescan(t *testing.T) {
	d := newDet(t)
	enc := base64.StdEncoding.EncodeToString([]byte(`{"password": "hunter22x"}`))

	// A secret inside base64 is found and mapped back to the encoded line.
	fs := d.ScanContent("secret.yml", []byte("data:\n  config.json: "+enc+"\n"))
	f := findSecret(fs, "hunter22x")
	if f == nil {
		t.Fatalf("decoded secret missed; got %v", ruleIDs(fs))
	}
	if f.Line != 2 || !strings.Contains(strings.Join(f.Tags, ","), "decoded:base64") || !strings.HasPrefix(f.Decoded, "base64: ") {
		t.Errorf("line=%d tags=%v decoded=%q", f.Line, f.Tags, f.Decoded)
	}

	// An encoded credential value carries its decoded form for the verifier.
	fs = d.ScanContent("recentservers.xml", []byte(`<Pass encoding="base64">`+base64.StdEncoding.EncodeToString([]byte("Tr0ub4dor&3"))+"</Pass>\n"))
	if len(fs) != 1 || fs[0].Decoded != "base64: Tr0ub4dor&3" {
		t.Errorf("want one candidate with decoded text; got %v %+v", ruleIDs(fs), fs)
	}

	// Percent-encoding hides the separator a URL credential needs.
	fs = d.ScanContent("run.sh", []byte("curl https%3A%2F%2Fdeploy%3AS3cr3tPw%40git.example.com%2Fx\n"))
	if findSecret(fs, "S3cr3tPw") == nil {
		t.Errorf("percent-encoded URL credential missed; got %v", ruleIDs(fs))
	}

	// Binary behind base64 is not text and yields nothing extra.
	bin := base64.StdEncoding.EncodeToString([]byte{0x89, 'P', 'N', 'G', 0, 1, 2, 3, 0xff, 0xfe, 0x10, 0x11})
	for _, f := range d.ScanContent("logo.txt", []byte("icon = "+bin+"\n")) {
		if len(f.Tags) > 1 {
			t.Errorf("binary decoded into a finding: %+v", f)
		}
	}

	// Depth 0 turns decoding off.
	cfg := config.Default()
	cfg.Scan.MaxDecodeDepth = 0
	off, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if findSecret(off.ScanContent("secret.yml", []byte("data:\n  config.json: "+enc+"\n")), "hunter22x") != nil {
		t.Error("max_decode_depth = 0 still decoded")
	}
}

func TestStructuralHonorsDisable(t *testing.T) {
	cfg := config.Default()
	cfg.Rules.Disable = []string{idPassword, idCredentialFile}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range d.ScanContent(".pgpass", []byte("password: hunter22\nlocalhost:5432:app:root:s3cret\n")) {
		if f.RuleID == idPassword || f.RuleID == idCredentialFile {
			t.Errorf("disabled stage fired: %s", f.RuleID)
		}
	}
}

func secrets(fs []finding.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Secret
	}
	return out
}
