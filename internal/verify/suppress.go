package verify

import (
	"fmt"
	"regexp"
	"strings"
)

// This file holds the structural false-positive suppressors used by the offline
// heuristic verifier. They exist because the no-AI path is what most CI runs
// actually execute (ai.mode=auto degrades to heuristics without credentials),
// so its precision — not just the AI path's — is what users experience.
//
// Every rule here keys off *code structure* rather than value entropy, and all
// but the placeholder-credential rule are gated to generic (entropy-only)
// matches. Provider-pattern rules (AKIA…, sk_live_…, ghp_…) are never
// suppressed by shape, so recall on real credentials is unaffected.

var (
	// commentRe matches a line whose first non-space content begins a comment
	// in the languages we scan (Ruby/Python/shell #, C-family //, block-comment
	// continuation *, SQL/Lua --, ini/asm ;).
	// The marker must be followed by whitespace or end-of-line: base64 key
	// material frequently begins with "//", and treating those lines as
	// comments silently dropped PEM private-key bodies.
	commentRe = regexp.MustCompile(`^\s*(#|//|\*|--|;)(\s|$)`)

	// rdocMarkupRe matches RDoc/Perl-POD style +identifier+ inline markup, e.g.
	// "+password_confirmation+". These are documentation tokens, not values.
	rdocMarkupRe = regexp.MustCompile(`\+[A-Za-z_][A-Za-z0-9_?!=]*\+`)

	// identifierRe matches a bare code identifier / dotted config key such as
	// "action_controller.csrf_token" or "_aj_hash_with_indifferent_access".
	// A credential is never shaped like this.
	identifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

	// bigIntRe matches a long pure-decimal literal, e.g. the uint64 sentinel
	// 18446744073709551615. Decimal integers are not credentials.
	bigIntRe = regexp.MustCompile(`^\d{12,}$`)

	// methodDefRe matches a Ruby writer-method definition or symbol reference
	// such as "def ignore_default_scope=(ignore)" or "private :_column=".
	methodDefRe = regexp.MustCompile(`(?:\bdef\s+|:)[A-Za-z_][A-Za-z0-9_]*=`)

	// codeExprRe matches a value that is unmistakably a code expression rather
	// than a credential: a call, an index, an argument list, or an interpolation.
	// Note: a bare space is deliberately NOT a signal here — "ssh-rsa AAAA..."
	// public-key lines contain one and are real key material.
	codeExprRe = regexp.MustCompile(`[()\[\]{},;]|::|#\{|\$\{`)

	// dottedCallRe matches a receiver.method chain such as "uri.password",
	// "ActiveStorage.verifier.verified" or "contextvars.Token". Constants are
	// capitalized in Ruby/Python, so both cases must be accepted.
	dottedCallRe = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_?!]*)+$`)

	// snakeIdentRe matches a snake_case identifier containing at least one
	// underscore, e.g. "generate_connection_token" or the Rails-internal
	// "_aj_hash_with_indifferent_access". Credentials are not word-structured
	// this way; local variables and config keys are.
	snakeIdentRe = regexp.MustCompile(`^@?_?[a-z][a-z0-9]*(_[a-z0-9]+)+$`)

	// symbolRe matches a Ruby symbol reference such as ":BCryptPassword".
	symbolRe = regexp.MustCompile(`^:[A-Za-z_][A-Za-z0-9_]*[?!]?$`)

	// uriCredsRe pulls the user:password pair out of a connection URI.
	uriCredsRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://([^:/@\s]+):([^@/\s]+)@`)
)

// uriHasPlaceholderCreds reports whether a connection URI's embedded
// credentials are conventional documentation placeholders — "foo:bar",
// "myuser:mypass", "postgres:postgres". A URI whose password is a real value
// is left alone, so genuine leaked DSNs still report.
func uriHasPlaceholderCreds(sec string) bool {
	m := uriCredsRe.FindStringSubmatch(sec)
	if m == nil {
		return false
	}
	user, pass := strings.ToLower(m[1]), strings.ToLower(m[2])
	return placeholderCreds[user] && placeholderCreds[pass]
}

// looksLikeCodeExpression reports whether an *unquoted* value is a program
// expression rather than a literal credential.
//
// This must stay narrow. An unquoted value is emphatically not enough on its
// own: PEM private-key bodies, .env values, /etc/shadow hashes and .htpasswd
// entries are all unquoted real secrets. Only values carrying positive syntactic
// evidence of being code — call/index punctuation, a dotted lowercase call
// chain, or a snake_case identifier — are suppressed here.
func looksLikeCodeExpression(sec string) bool {
	return codeExprRe.MatchString(sec) ||
		dottedCallRe.MatchString(sec) ||
		snakeIdentRe.MatchString(sec)
}

// knownDigests are well-known constant hashes that appear in self-test code
// (e.g. the md5("hello") vector shipped inside SparkMD5). They are published
// values, not secrets.
var knownDigests = map[string]bool{
	"5d41402abc4b2a76b9719d911017c592":                                 true, // md5("hello")
	"d41d8cd98f00b204e9800998ecf8427e":                                 true, // md5("")
	"098f6bcd4621d373cade4e832627b4f6":                                 true, // md5("test")
	"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         true, // sha1("")
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": true, // sha256("")
}

// placeholderCreds are user/password values used in documentation and CI
// service definitions. A credential equal to its own role name ("postgres" as
// the postgres password) carries no secret information.
var placeholderCreds = map[string]bool{
	"postgres": true, "mysql": true, "root": true, "admin": true,
	"user": true, "username": true, "pass": true, "password": true,
	"foo": true, "bar": true, "baz": true, "mypass": true, "myuser": true,
	"badpass": true, "baduser": true, "cachepass": true, "cacheuser": true,
	"guest": true, "demo": true, "local": true, "localhost": true,
}

// docExts are prose/markup formats whose code samples are illustrative by
// construction. Deliberately excludes .txt, which is a common dumping ground
// for genuine credential material (leaky-repo's high-entropy-misc.txt).
var docExts = map[string]bool{
	".rst": true, ".md": true, ".adoc": true, ".rdoc": true, ".textile": true,
}

// docNames are conventional extensionless prose files. They carry usage text
// and command examples ("bin/rails generate model user password:digest") that
// read as assignments to a generic rule, but they are documentation by
// convention in every ecosystem that uses them.
var docNames = map[string]bool{
	"usage": true, "readme": true, "changelog": true, "changes": true,
	"contributing": true, "license": true, "licence": true, "copying": true,
	"notice": true, "authors": true, "install": true, "news": true, "todo": true,
}

// isDocFile reports whether path is prose documentation. Only entropy-only
// matches are suppressed on this basis; a provider-pattern hit (a live AKIA…
// key pasted into a tutorial) still reports, because that is a real leak.
func isDocFile(path string) bool {
	p := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if docNames[p] {
		return true
	}
	ext := ""
	if i := strings.LastIndex(p, "."); i >= 0 {
		ext = p[i:]
	}
	return docExts[ext]
}

// matchedLine pulls the exact source line the candidate was found on out of the
// context snippet, which is rendered by the detector as "<line number>: <text>".
// It returns "" when the line cannot be located, so callers stay conservative.
func matchedLine(r Request) string {
	prefix := fmt.Sprintf("%d: ", r.Line)
	for _, l := range strings.Split(r.Context, "\n") {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimPrefix(l, prefix)
		}
	}
	return ""
}

// secretIsQuoted reports whether the candidate value appears inside a string
// literal on the given line. A hardcoded credential is by definition a literal;
// an unquoted occurrence is an identifier or expression (`password = user.pass`,
// `token = generate_token`) and cannot itself be a leaked value.
//
// It returns true when the line is unavailable or the value cannot be located,
// so an unparseable line is never suppressed on this basis.
func secretIsQuoted(line, secret string) bool {
	if line == "" || secret == "" {
		return true
	}
	idx := strings.Index(line, secret)
	if idx < 0 {
		return true // cannot locate the value: do not suppress
	}
	// Count unescaped quote characters preceding the value. An odd count of any
	// quote style means the value sits inside an open string literal.
	for _, q := range []byte{'"', '\'', '`'} {
		n := 0
		for i := 0; i < idx; i++ {
			if line[i] == q && (i == 0 || line[i-1] != '\\') {
				n++
			}
		}
		if n%2 == 1 {
			return true
		}
	}
	return false
}

// structuralFP reports a reason when the candidate is a structural false
// positive, or "" when no suppressor fires. `generic` gates the rules that are
// only safe for entropy-only matches.
func structuralFP(r Request, generic bool) string {
	line := matchedLine(r)
	sec := r.Secret

	// Placeholder credentials apply to every rule, including connection-URI
	// patterns, because "postgres://postgres:postgres@localhost" is a documented
	// example no matter how confidently the URI pattern matched.
	if placeholderCreds[strings.ToLower(sec)] {
		return "value is a conventional placeholder credential, not a real one"
	}
	if knownDigests[strings.ToLower(sec)] {
		return "value is a well-known published digest constant used in self-tests"
	}
	if uriHasPlaceholderCreds(sec) {
		return "connection URI carries placeholder credentials, not real ones"
	}
	// An interpolated value is assembled at runtime; the literal in the source
	// is a template, not a credential. True whether or not it sits in quotes.
	if strings.Contains(sec, "#{") || strings.Contains(sec, "${") {
		return "value is a runtime string interpolation, not a literal credential"
	}
	// A command-line flag captured as an assignment value ("--password").
	if strings.HasPrefix(sec, "--") {
		return "value is a command-line flag, not a credential"
	}

	// Everything below is entropy-only territory: never applied to a provider
	// pattern match, so real credentials keep their recall.
	if !generic {
		return ""
	}

	if line != "" && commentRe.MatchString(line) {
		return "candidate appears on a comment/documentation line"
	}
	if isDocFile(r.FilePath) {
		return "entropy-only match inside a documentation file"
	}
	if bigIntRe.MatchString(sec) {
		return "value is a decimal integer literal, not a credential"
	}
	// The candidate must itself be the marked-up token (+the_secret+), not merely
	// sit on a line containing a "+...+" pair: base64 key material is full of
	// '+' characters and "+SY+Yv0J..." otherwise reads as RDoc markup.
	if line != "" && identifierRe.MatchString(sec) &&
		rdocMarkupRe.MatchString("+"+sec+"+") && strings.Contains(line, "+"+sec+"+") {
		return "candidate is RDoc +markup+ inline documentation, not a value"
	}
	if line != "" && methodDefRe.MatchString(line) {
		return "candidate is a method/attribute definition, not a value"
	}
	if line != "" && !secretIsQuoted(line, sec) && looksLikeCodeExpression(sec) {
		return "candidate is a code expression/identifier, not a string literal"
	}
	// A *quoted* value may still be a config key rather than a credential
	// ("action_controller.csrf_token"). Require a dotted or snake_case shape so
	// that opaque lowercase tokens (real keys) are never caught here.
	if dottedCallRe.MatchString(sec) || snakeIdentRe.MatchString(sec) || symbolRe.MatchString(sec) {
		return "value is an identifier/symbol/config key, not a credential"
	}

	return ""
}
