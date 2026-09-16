package detect

// Structural stages: credential assignments, credential files, URL credentials
// and login calls. There is no rule catalog here. Each stage answers one
// question -- is a literal value bound to something named like a credential? --
// and leaves the judgement to the verifier.
//
// There is deliberately no entropy floor. "admin", "pass123" and "hunter22" are
// real leaks, and an entropy gate is exactly what dropped them.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/0x1Adi/Klarion/internal/entropy"
	"github.com/0x1Adi/Klarion/internal/finding"
)

const (
	idPassword       = "generic-password-assignment" // klarion:allow (rule ID)
	idSecret         = "generic-secret-assignment"   // klarion:allow (rule ID)
	idURLCredentials = "url-credentials"             // klarion:allow (rule ID)
	idCredentialFile = "credential-file-entry"

	minValueLen          = 4
	maxValueLen          = 1024
	relatedRadius        = 6 // lines searched for user=/host= around a credential
	maxRelated           = 4
	maxCredentialEntries = 20 // per file
	maxBlockValueLines   = 64
)

// keyClass ranks what a key name says about its value.
type keyClass uint8

const (
	keyNone     keyClass = iota
	keyIdentity          // user, host, login: context for the verifier, never a candidate
	keyWeak              // key, salt, auth: a candidate only when the value is secret-shaped
	keySecret            // secret, token, credential, api key
	keyPassword          // pass, passwd, password, passphrase, pwd
)

// candidate is a value located by a structural stage, before it is a finding.
type candidate struct {
	idx        int // index into lines of the line holding the value
	start, end int // byte span of the value on that line
	keyStart   int // where the key begins on the scanned line; the stages after
	// this one must not re-report the key name as a high-entropy token
	secret     string
	rule, desc string
	sev        finding.Severity
	tags       []string
	related    bool  // attach nearby user=/host= parts
	coverLines []int // further lines the value spans (YAML block scalars)
}

var (
	// assignRe finds `key <sep>`. The key may be quoted (JSON, PHP define, dict
	// literals) or bracketed (ENV['X'] = ...). The value is read separately from
	// the end of the match, so quoted values may hold any punctuation.
	assignRe = regexp.MustCompile(`(?:^|[^\w$@.\-])(["'\x60]?)([$@]{0,2}[A-Za-z_][\w.\-]*)(["'\x60]?)\]?\s*(:=|===?|!==?|=>|=|:|,)[ \t]*`)

	xmlElemRe = regexp.MustCompile(`<([A-Za-z_][\w.:\-]*)(?:\s[^<>]*)?>([^<]+)</([A-Za-z_][\w.:\-]*)>`)
	xmlOpenRe = regexp.MustCompile(`<([A-Za-z_][\w.:\-]*)(?:\s[^<>]*)?>\s*$`)

	// pairTokRe tokenizes "word value" lines (netrc, esmtprc).
	pairTokRe  = regexp.MustCompile(`"[^"]*"|'[^']*'|\S+`)
	bareWordRe = regexp.MustCompile(`^[A-Za-z][A-Za-z_\-]*$`)

	// urlCredRe matches scheme://user:password@host. The password may contain
	// '@' (it backtracks to the last @host) but not '/', which keeps
	// host:port/@scope paths from reading as credentials.
	urlCredRe = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]{1,20}://([^\s:/@"'\x60<>]+(?:@[^\s:/@"'\x60<>]+)?):([^\s/"'\x60<>]+)@([A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?:[:/?#\s"'\x60<>,;)\]}]|$)`)

	loginCallRe = regexp.MustCompile(`(?i)\b(?:log_?in|log_?on|sign_?in|authenticate|basic_?auth|set_?credentials)\s*\(\s*`)

	blockScalarRe = regexp.MustCompile(`^[|>][-+]?\d*(?:\s+#.*)?$`)

	// varRefRe matches values that name a value instead of being one: $VAR,
	// %VAR%, <placeholder>, [[ref]], :symbol.
	varRefRe = regexp.MustCompile(`^(?:\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|<[^<>]*>|\[\[[^\]]*\]\]|:[A-Za-z_]\w*)$`)
	// templateRe matches interpolation anywhere in a value: ${X}, {{ x }}, #{x},
	// <%= x %>, $(cmd), %s, {0}. It needs the closing delimiter, so a WordPress
	// salt that happens to contain "#{" is still a value, and printf verbs take
	// no width, so a URL-encoded "p%40ss" is too.
	templateRe = regexp.MustCompile(`\$\{[^}]*\}|\{\{[^}]*\}\}|#\{[^}]*\}|<%.*%>|\$\([^)]*\)|%[-+ #0]?\.?[sdvqf]|\{\d*\}`)
	pathRe     = regexp.MustCompile(`^(?:~?/|\.\.?/|[A-Za-z]:\\)`)
)

// metaSuffix marks keys that describe a credential rather than hold one:
// password_field, token_type, secret_name, password_file.
var metaSuffix = map[string]bool{
	"field": true, "name": true, "label": true, "type": true, "placeholder": true,
	"hint": true, "prompt": true, "policy": true, "length": true, "len": true,
	"pattern": true, "regex": true, "format": true, "file": true, "path": true,
	"dir": true, "env": true, "var": true, "header": true, "param": true,
	"url": true, "uri": true, "endpoint": true, "expiry": true, "expires": true,
	"expiration": true, "ttl": true, "count": true, "enabled": true,
	"required": true, "confirmation": true, "reset": true, "min": true, "max": true,
	"changed": true, "updated": true, "created": true, "modified": true, "date": true,
	"time": true, "timestamp": true, "at": true, "age": true, "attempts": true,
}

// passWords end in "pass" without being one.
var passWords = map[string]bool{
	"bypass": true, "compass": true, "surpass": true, "trespass": true,
	"overpass": true, "underpass": true, "encompass": true,
}

// nonValues are literals that configure a credential instead of being one.
var nonValues = map[string]bool{
	"true": true, "false": true, "null": true, "nil": true, "none": true,
	"undefined": true, "yes": true, "no": true, "on": true, "off": true,
	"required": true, "optional": true, "empty": true, "string": true,
	"bool": true, "boolean": true, "integer": true, "number": true,
	"prompt": true, "stdin": true, "keyring": true, "keychain": true,
}

// quotedExt lists source and prose formats, where an unquoted right-hand side
// is an expression, a type or a sentence rather than a value.
var quotedExt = map[string]bool{
	".go": true, ".py": true, ".rb": true, ".js": true, ".jsx": true, ".mjs": true,
	".cjs": true, ".ts": true, ".tsx": true, ".java": true, ".kt": true, ".kts": true,
	".scala": true, ".groovy": true, ".gradle": true, ".cs": true, ".vb": true,
	".php": true, ".c": true, ".h": true, ".cc": true, ".cpp": true, ".cxx": true,
	".hpp": true, ".m": true, ".mm": true, ".swift": true, ".rs": true, ".dart": true,
	".lua": true, ".pl": true, ".pm": true, ".ex": true, ".exs": true, ".erl": true,
	".clj": true, ".hs": true, ".fs": true, ".r": true, ".jl": true, ".vue": true,
	".svelte": true, ".sql": true, ".graphql": true, ".gql": true, ".proto": true,
	".tf": true, ".hcl": true, ".ps1": true, ".psm1": true, ".md": true,
	".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".s": true, ".asm": true,
}

// dataExt lists formats a credential store is written in. A name-derived
// credential file must be one of these (or extensionless): password_reset.rb
// names a feature, not a store.
var dataExt = map[string]bool{
	".txt": true, ".conf": true, ".cfg": true, ".cnf": true, ".ini": true,
	".json": true, ".xml": true, ".yml": true, ".yaml": true, ".env": true,
	".properties": true, ".csv": true, ".toml": true, ".list": true, ".bak": true,
}

// splitKey lowercases a key and splits it into words across snake, kebab, dot
// and camel boundaries: "AdminPassword" -> [admin password], "IRC_PASS" ->
// [irc pass], "APIKey" -> [api key].
func splitKey(k string) []string {
	var segs []string
	rs := []rune(k)
	start := -1
	flush := func(end int) {
		if start >= 0 {
			segs = append(segs, strings.ToLower(string(rs[start:end])))
			start = -1
		}
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush(i)
			continue
		}
		if start >= 0 && unicode.IsUpper(r) {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(rs))
	return segs
}

func classifyKey(key string) keyClass {
	segs := splitKey(key)
	n := len(segs)
	if n == 0 || (n > 1 && metaSuffix[segs[n-1]]) {
		return keyNone
	}
	// A bare upper-case PASS is a test status ("--- PASS: TestX"), not a key.
	if n == 1 && segs[0] == "pass" && strings.ToUpper(key) == key {
		return keyNone
	}
	class := keyNone
	for i, s := range segs {
		switch {
		case s == "pass" || s == "pwd" || strings.Contains(s, "passw") ||
			strings.HasPrefix(s, "passphrase") || strings.HasPrefix(s, "passcode") ||
			(strings.HasSuffix(s, "pass") && !passWords[s]) || strings.HasSuffix(s, "pwd"):
			return keyPassword
		case strings.Contains(s, "secret") || s == "token" || s == "tokens" ||
			strings.HasSuffix(s, "token") || strings.Contains(s, "credential") ||
			s == "creds" || strings.Contains(s, "apikey") || (s == "key" && i > 0 && segs[i-1] == "api"):
			class = max(class, keySecret)
		case (s == "key" && i > 0 && segs[i-1] != "public") || s == "salt" ||
			strings.HasSuffix(s, "salt") || s == "auth" || qualifiedKey(s):
			class = max(class, keyWeak)
		case i == n-1 && identityWord(s):
			class = max(class, keyIdentity)
		}
	}
	// An *_id names a principal, not a secret: access_key_id, client_id.
	if segs[n-1] == "id" && class == keyWeak {
		return keyIdentity
	}
	return class
}

// classifyAssignKey classifies the last component of a dotted or namespaced
// key: db.password is a password, token.XOR is a constant in package token.
func classifyAssignKey(key string) keyClass {
	if i := strings.LastIndexAny(key, ".:"); i >= 0 && i < len(key)-1 {
		key = key[i+1:]
	}
	return classifyKey(key)
}

func qualifiedKey(s string) bool {
	if !strings.HasSuffix(s, "key") || len(s) <= 3 {
		return false
	}
	for _, q := range []string{"private", "access", "master", "signing", "encryption", "auth", "session", "client", "app"} {
		if strings.HasPrefix(s, q) {
			return true
		}
	}
	return false
}

func identityWord(s string) bool {
	switch s {
	case "login", "email", "account", "machine", "server", "database", "url", "uri", "endpoint", "id":
		return true
	}
	return strings.HasSuffix(s, "user") || strings.HasSuffix(s, "username") || strings.HasSuffix(s, "host") || s == "hostname"
}

// hasCredentialWord is a cheap prescreen before any structural regex runs.
func hasCredentialWord(lower string) bool {
	for _, w := range []string{"pass", "pwd", "secret", "token", "cred", "key", "salt", "auth"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// needsQuotes reports whether values in this file must be quoted literals:
// source code, and prose (README, CHANGELOG), where "PASS: TestX" or "pass
// through a hole" is a sentence.
func needsQuotes(p string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	for _, prose := range []string{"readme", "changelog", "changes", "history", "news", "license", "copying", "notice", "authors", "contributing"} {
		if strings.HasPrefix(base, prose) {
			return true
		}
	}
	i := strings.LastIndexByte(base, '.')
	return i > 0 && quotedExt[base[i:]]
}

// credentialFile reports whether a file's own name says it stores credentials
// (.pgpass, .git-credentials, .htpasswd, secrets.yml). The name is the key.
func credentialFile(p string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	stem := base
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		if !dataExt[base[i:]] {
			return false
		}
		stem = base[:i]
	}
	return classifyKey(stem) >= keySecret
}

// readValue reads the literal starting at s[i]. Quoted literals end at the
// matching unescaped quote; unquoted ones at whitespace or a delimiter.
func readValue(s string, i int, requireQuote bool) (val string, start, end int, ok bool) {
	if i >= len(s) {
		return "", 0, 0, false
	}
	switch q := s[i]; q {
	case '"', '\'', '`':
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
				continue
			}
			if s[j] == q {
				return s[i+1 : j], i + 1, j, true
			}
		}
		return "", 0, 0, false
	}
	if requireQuote {
		return "", 0, 0, false
	}
	j := i
	for j < len(s) && !strings.ContainsRune(" \t,;<>)]}", rune(s[j])) {
		j++
	}
	if j == i {
		return "", 0, 0, false
	}
	return s[i:j], i, j, true
}

// literal reports whether v is a value rather than a reference, a template, a
// type, a path or a placeholder.
func (d *Detector) literal(v string, quoted bool) bool {
	if len(v) < minValueLen || len(v) > maxValueLen {
		return false
	}
	if templateRe.MatchString(v) || varRefRe.MatchString(v) || pathRe.MatchString(v) ||
		strings.HasPrefix(v, "${") || strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "#{") {
		return false
	}
	if !quoted && (strings.ContainsAny(v[:1], "([{") || strings.Contains(v, "(")) {
		return false
	}
	if strings.Count(v, " ") >= 4 || strings.Contains(v, `\n`) {
		return false // a sentence or a docstring, not a passphrase
	}
	lv := strings.ToLower(v)
	return !nonValues[lv] && !sameChar(v) && !d.anchoredPlaceholder(lv) && !d.cfg.SecretAllowlisted(v)
}

// anchoredPlaceholder matches stopwords against the whole value. The detector's
// substring check made "UserPassword123" a placeholder because it contains
// "password123"; here only "password123" itself (or "example42") is one.
// User-configured stopwords keep their documented substring semantics.
func (d *Detector) anchoredPlaceholder(lv string) bool {
	base := strings.TrimRight(lv, "0123456789")
	for _, w := range d.stopwords {
		prefix := strings.HasSuffix(w, "_") || strings.HasSuffix(w, "-") || strings.HasPrefix(w, "<")
		if lv == w || base == w || (prefix && strings.HasPrefix(lv, w)) {
			return true
		}
	}
	for _, w := range d.userStopwords {
		if strings.Contains(lv, w) {
			return true
		}
	}
	return false
}

func sameChar(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// secretShaped gates weak keys (auth_key, salt): mixed classes, punctuation, or
// high entropy. It keeps cache keys built from words and ids out.
func secretShaped(v string) bool {
	if len(v) < 12 || strings.Contains(v, "://") {
		return false
	}
	var up, lo, dg, sym bool
	letters, spaces := 0, 0
	for _, r := range v {
		switch {
		case unicode.IsUpper(r):
			up, letters = true, letters+1
		case unicode.IsLower(r):
			lo, letters = true, letters+1
		case unicode.IsDigit(r):
			dg = true
		case r == ' ':
			spaces++
		case strings.ContainsRune("_-.:/", r):
		default:
			sym = true
		}
	}
	if spaces >= 2 && float64(letters+spaces) >= 0.85*float64(len(v)) {
		return false // prose
	}
	return (up && lo && dg) || sym || (dg && len(v) >= 16 && entropy.NormalizedScore(v) >= 0.8)
}

// valueCandidate turns a located value into a candidate if it survives the
// literal and shape checks for its key class.
func (d *Detector) valueCandidate(idx, start, end int, val string, class keyClass, quoted bool) (candidate, bool) {
	if class < keyWeak || !d.literal(val, quoted) || (class == keyWeak && (!secretShaped(val) || identifierLike(val))) {
		return candidate{}, false
	}
	c := candidate{idx: idx, start: start, end: end, secret: val, sev: finding.SeverityMedium,
		tags: []string{"generic"}, related: true,
		rule: idSecret, desc: "Value assigned to a secret/token/key name"}
	if class == keyPassword {
		c.rule, c.desc = idPassword, "Value assigned to a password name"
	}
	return c, true
}

// callArg reports whether the quoted key at q is a call's first argument:
// define('DB_PASSWORD', 'x'), setenv("TOKEN", "x"). A comma elsewhere
// separates list items, not a key from its value.
func callArg(s string, q int) bool {
	for q > 0 && (s[q-1] == ' ' || s[q-1] == '\t') {
		q--
	}
	return q > 0 && s[q-1] == '('
}

func mixedCase(s string) bool {
	return strings.ToLower(s) != s && strings.ToUpper(s) != s
}

func skipSpaces(s string, p int) int {
	for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	return p
}

// identifierLike reports a value shaped like a symbol name or a composite key
// -- KeySize768, keyGen768, user:profile:42 -- rather than key
// material: few, long, letter-heavy words. Hex and base64 fail it on letter
// ratio or segment count. Used for weak keys only: a human-chosen password such
// as "swordfish" is word-shaped too.
func identifierLike(v string) bool {
	letters := 0
	for _, r := range v {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r) || strings.ContainsRune("_-.:/", r):
		default:
			return false
		}
	}
	segs := splitKey(v)
	return len(segs) <= 6 && letters*10 >= len(v)*6 && len(v) >= 3*len(segs)
}

func group(s string, m []int, g int) string {
	if m[2*g] < 0 {
		return ""
	}
	return s[m[2*g]:m[2*g+1]]
}

// structural returns the candidates located on lines[i]. A value that starts on
// a following line (YAML block scalar, split XML element, continuation) comes
// back with idx pointing at the line that holds it.
func (d *Detector) structural(lines []Line, i int, text, lower string, quotedOnly bool) []candidate {
	var out []candidate
	if hasCredentialWord(lower) {
		out = append(out, d.assignments(lines, i, text, quotedOnly)...)
	}
	if strings.Contains(text, "://") && strings.Contains(text, "@") {
		for _, m := range urlCredRe.FindAllStringSubmatchIndex(text, maxMatchesPerLine) {
			pw := group(text, m, 2)
			if !d.literal(pw, true) {
				continue
			}
			out = append(out, candidate{idx: i, start: m[4], end: m[5], keyStart: m[0], secret: pw,
				rule: idURLCredentials, desc: "Credentials embedded in a URL (user:password@host)",
				sev: finding.SeverityHigh, tags: []string{"url"}})
		}
	}
	if strings.Contains(lower, "log") || strings.Contains(lower, "sign") || strings.Contains(lower, "auth") || strings.Contains(lower, "cred") {
		for _, m := range loginCallRe.FindAllStringIndex(text, 4) {
			// login(user, pass): the last of two or more leading
			// literal arguments is the credential.
			var val string
			var vs, ve, n int
			for p := m[1]; n < 4; n++ {
				v, s, e, ok := readValue(text, p, true)
				if !ok {
					break
				}
				val, vs, ve = v, s, e
				p = skipSpaces(text, e+1)
				if p >= len(text) || text[p] != ',' {
					n++
					break
				}
				p = skipSpaces(text, p+1)
			}
			if n >= 2 && d.literal(val, true) {
				out = append(out, candidate{idx: i, start: vs, end: ve, keyStart: m[0], secret: val, rule: idPassword,
					desc: "Password passed to a login call", sev: finding.SeverityMedium, tags: []string{"generic"}})
			}
		}
	}
	return out
}

func (d *Detector) assignments(lines []Line, i int, text string, quotedOnly bool) []candidate {
	var out []candidate
	var keyStart int
	add := func(c candidate, ok bool) {
		if ok {
			c.keyStart = keyStart
			out = append(out, c)
		}
	}
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, maxMatchesPerLine) {
		q1, key, q3, sep := group(text, m, 1), group(text, m, 2), group(text, m, 3), group(text, m, 4)
		class := classifyAssignKey(key)
		if q1 != q3 || class < keyWeak {
			continue
		}
		// define('DB_PASSWORD', 'x') is a key and its value; namedtuple('TokenInfo',
		// 'type string') is a call on a symbol. Outside the password class a call
		// argument must look like a config key, not a CamelCase name.
		if sep == "," && (q1 == "" || !callArg(text, m[2]) || (class != keyPassword && mixedCase(key))) {
			continue
		}
		// A token compared to a keyword is a lexer; a password compared to a
		// literal is a hardcoded check.
		if (sep[0] == '!' || strings.HasPrefix(sep, "==")) && class != keyPassword {
			continue
		}
		vs := m[1]
		keyStart = m[2]
		if sep == ":" && vs < len(text) && text[vs] == ':' {
			continue // scope operator, not a separator
		}
		needQuote := quotedOnly || sep == "," || sep[0] == '!' || strings.HasPrefix(sep, "==")
		if rest := strings.TrimSpace(text[vs:]); rest == "" || rest == `\` || (!needQuote && blockScalarRe.MatchString(rest)) {
			add(d.nextLineValue(lines, i, rest, needQuote, class))
		} else if val, s, e, ok := readValue(text, vs, needQuote); ok {
			add(d.valueCandidate(i, s, e, val, class, s > vs))
		}
	}
	for _, m := range xmlElemRe.FindAllStringSubmatchIndex(text, maxMatchesPerLine) {
		if group(text, m, 1) != group(text, m, 3) {
			continue
		}
		raw := group(text, m, 2)
		val := strings.TrimSpace(raw)
		s := m[4] + strings.Index(raw, val)
		keyStart = m[0]
		add(d.valueCandidate(i, s, s+len(val), val, classifyAssignKey(group(text, m, 1)), true))
	}
	if m := xmlOpenRe.FindStringSubmatch(text); m != nil && !quotedOnly {
		if class := classifyAssignKey(m[1]); class >= keyWeak && i+1 < len(lines) && lines[i+1].Number == lines[i].Number+1 {
			next := lines[i+1].Text
			val := strings.TrimSpace(next)
			if k := strings.Index(val, "</"); k >= 0 {
				val = strings.TrimSpace(val[:k])
			}
			if val != "" && val[0] != '<' {
				s := strings.Index(next, val)
				keyStart = strings.Index(text, "<")
				add(d.valueCandidate(i+1, s, s+len(val), val, class, true))
			}
		}
	}
	if !quotedOnly {
		ps := pairs(text)
		for _, p := range ps {
			keyStart = p.keyStart
			add(d.valueCandidate(i, p.start, p.end, p.val, pairClass(p.key, ps), p.quoted))
		}
	}
	return out
}

// pairClass admits a whitespace pair only in credential-file shape. The key must
// be a full password word, and a line with several pairs must also name who or
// where (netrc's machine/login): otherwise "pass through a small round hole"
// is a credential.
func pairClass(key string, all []kvPair) keyClass {
	switch strings.ToLower(key) {
	case "password", "passwd", "passphrase":
	default:
		return keyNone
	}
	if len(all) == 1 {
		return keyPassword
	}
	for _, p := range all {
		if classifyKey(p.key) == keyIdentity {
			return keyPassword
		}
	}
	return keyNone
}

type kvPair struct {
	key, val             string
	keyStart, start, end int
	quoted               bool
}

// pairs splits lines made only of "word value" pairs: netrc's
// "machine h login u password p", esmtprc's `password "p"`.
func pairs(text string) []kvPair {
	toks := pairTokRe.FindAllStringIndex(text, 17)
	if len(toks) < 2 || len(toks)%2 != 0 || len(toks) > 16 {
		return nil
	}
	var out []kvPair
	for k := 0; k < len(toks); k += 2 {
		key := text[toks[k][0]:toks[k][1]]
		if !bareWordRe.MatchString(key) {
			return nil
		}
		s, e := toks[k+1][0], toks[k+1][1]
		quoted := e-s >= 2 && strings.ContainsRune(`"'`, rune(text[s])) && text[e-1] == text[s]
		if quoted {
			s, e = s+1, e-1
		}
		out = append(out, kvPair{key: key, val: text[s:e], keyStart: toks[k][0], start: s, end: e, quoted: quoted})
	}
	return out
}

// nextLineValue handles a credential key whose value starts on the next line:
// a YAML block scalar (password: |), a continuation (PASSWORD = \), or a value
// on a deeper-indented or quoted line of its own.
func (d *Detector) nextLineValue(lines []Line, i int, rest string, needQuote bool, class keyClass) (candidate, bool) {
	j := i + 1
	if j >= len(lines) || lines[j].Number != lines[i].Number+1 {
		return candidate{}, false
	}
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " \t")) }
	next := lines[j].Text
	trimmed := strings.TrimSpace(next)
	if trimmed == "" {
		return candidate{}, false
	}
	switch {
	case !needQuote && blockScalarRe.MatchString(rest):
		base := indent(lines[i].Text)
		var parts []string
		var cover []int
		for k := j; k < len(lines) && k-j < maxBlockValueLines; k++ {
			t := lines[k].Text
			if (k > j && lines[k].Number != lines[k-1].Number+1) || strings.TrimSpace(t) == "" || indent(t) <= base {
				break
			}
			parts = append(parts, strings.TrimSpace(t))
			if k > j {
				cover = append(cover, k)
			}
		}
		if len(parts) == 0 {
			return candidate{}, false
		}
		c, ok := d.valueCandidate(j, indent(next), len(next), strings.Join(parts, "\n"), class, true)
		c.coverLines = cover
		return c, ok
	case rest == "" || rest == `\`:
		if strings.ContainsRune("\"'`", rune(trimmed[0])) {
			val, s, e, ok := readValue(next, indent(next), true)
			if !ok {
				return candidate{}, false
			}
			return d.valueCandidate(j, s, e, val, class, true)
		}
		if needQuote || indent(next) <= indent(lines[i].Text) || assignRe.MatchString(next) {
			return candidate{}, false
		}
		val, s, e, ok := readValue(next, indent(next), false)
		if !ok {
			return candidate{}, false
		}
		return d.valueCandidate(j, s, e, val, class, false)
	}
	return candidate{}, false
}

// related collects identity fields (user=, host=, login=) near a credential so
// a record split across lines -- FileZilla's <Host>/<User>/<Pass>, a netrc
// entry -- reaches the verifier whole even when it is outside the context
// window.
func related(lines []Line, idx int, quotedOnly bool) string {
	type part struct {
		dist int
		text string
	}
	var parts []part
	for j := max(0, idx-relatedRadius); j < len(lines) && j <= idx+relatedRadius; j++ {
		dist := lines[j].Number - lines[idx].Number
		if dist < -relatedRadius || dist > relatedRadius {
			continue
		}
		for _, p := range identityPairs(lines[j].Text, quotedOnly) {
			parts = append(parts, part{max(dist, -dist), fmt.Sprintf("%s=%s (line %d)", p.key, p.val, lines[j].Number)})
		}
	}
	sort.SliceStable(parts, func(a, b int) bool { return parts[a].dist < parts[b].dist })
	var out []string
	seen := map[string]bool{}
	for _, p := range parts {
		if len(out) == maxRelated {
			break
		}
		if !seen[p.text] {
			seen[p.text] = true
			out = append(out, p.text)
		}
	}
	return strings.Join(out, "; ")
}

func identityPairs(text string, quotedOnly bool) []kvPair {
	var out []kvPair
	keep := func(key, val string) {
		val = strings.TrimSpace(val)
		if classifyAssignKey(key) == keyIdentity && val != "" && len(val) <= 100 {
			out = append(out, kvPair{key: key, val: val})
		}
	}
	for _, m := range assignRe.FindAllStringSubmatchIndex(text, maxMatchesPerLine) {
		if val, _, _, ok := readValue(text, m[1], quotedOnly); ok && group(text, m, 1) == group(text, m, 3) {
			keep(group(text, m, 2), val)
		}
	}
	for _, m := range xmlElemRe.FindAllStringSubmatchIndex(text, maxMatchesPerLine) {
		if group(text, m, 1) == group(text, m, 3) {
			keep(group(text, m, 1), group(text, m, 2))
		}
	}
	if !quotedOnly {
		for _, p := range pairs(text) {
			keep(p.key, p.val)
		}
	}
	return out
}

// credentialEntries flags records in a name-derived credential file that no
// other stage explained: .pgpass host:port:db:user:password lines, .htpasswd
// user:hash lines, a bare token in token.txt.
func (d *Detector) credentialEntries(path string, lines []Line, found []finding.Finding) []finding.Finding {
	if d.disabled[idCredentialFile] {
		return nil
	}
	// A line explained by a real stage is skipped. An entropy fragment of the
	// record (the tail of an $apr1$ hash) is not an explanation: the whole
	// record replaces it.
	has := make(map[int]bool, len(found))
	for _, f := range found {
		if f.RuleID != "generic-high-entropy" {
			has[f.Line] = true
		}
	}
	var out []finding.Finding
	for i, ln := range lines {
		if len(out) == maxCredentialEntries {
			break
		}
		t := strings.TrimSpace(ln.Text)
		if has[ln.Number] || hasAllowMarker(t) || !credentialRecord(t) || !d.literal(t, true) {
			continue
		}
		start := strings.Index(ln.Text, t)
		if f := d.newFinding(path, lines, i, ln, idCredentialFile,
			"Record in a file whose name marks it as a credential store",
			finding.SeverityHigh, []string{"credential-file"}, t, start, start+len(t)); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func credentialRecord(t string) bool {
	if len(t) < 8 || len(t) > 512 || strings.ContainsAny(t, " \t") || strings.HasSuffix(t, ":") || strings.HasPrefix(t, "//") {
		return false
	}
	if strings.ContainsRune("#;<{}[]", rune(t[0])) {
		return false
	}
	return strings.ContainsAny(t, ":=@") || (len(t) >= 16 && !strings.ContainsAny(t, ",;|/"))
}
