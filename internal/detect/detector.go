// Package detect implements Klarion's fast detection pass: curated rules for
// known secret formats plus a normalized Rényi-entropy sweep for generic
// high-entropy material. Its output is a set of candidate findings that the
// verification stage (internal/verify) adjudicates.
package detect

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/entropy"
	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/rules"
)

const (
	maxLineScanLen     = 50_000 // longer lines are truncated before scanning
	maxMatchesPerLine  = 10
	maxFindingsPerFile = 200
	contextRadius      = 3    // lines of context captured around a finding
	maxContextChars    = 1500 // total cap on the context snippet
	maxContextLineLen  = 200  // per-line cap inside the context snippet
)

// Line pairs a line number with its text; ScanLines accepts arbitrary
// (possibly non-contiguous) line sets, e.g. the added lines of a git diff.
type Line struct {
	Number int
	Text   string
}

// Detector is safe for concurrent use once constructed.
type Detector struct {
	cfg       *config.Config
	rules     []rules.Rule
	stopwords []string
}

// New builds a detector from the config: built-in rules (minus disabled ones)
// plus compiled custom rules.
func New(cfg *config.Config) (*Detector, error) {
	disabled := make(map[string]bool, len(cfg.Rules.Disable))
	for _, id := range cfg.Rules.Disable {
		disabled[id] = true
	}
	var rs []rules.Rule
	for _, r := range rules.Builtin() {
		if !disabled[r.ID] {
			rs = append(rs, r)
		}
	}
	for _, c := range cfg.Rules.Custom {
		if disabled[c.ID] {
			continue
		}
		re, err := regexp.Compile(c.Regex)
		if err != nil {
			return nil, fmt.Errorf("custom rule %q: %w", c.ID, err)
		}
		rs = append(rs, rules.Rule{
			ID:          c.ID,
			Description: c.Description,
			Regex:       re,
			SecretGroup: c.SecretGroup,
			Keywords:    lowerAll(c.Keywords),
			Entropy:     c.Entropy,
			MinLen:      c.MinLen,
			MaxLen:      c.MaxLen,
			Severity:    finding.ParseSeverity(c.Severity),
			Tags:        c.Tags,
		})
	}
	return &Detector{cfg: cfg, rules: rs, stopwords: lowerAll(cfg.Stopwords())}, nil
}

// Rules returns the active ruleset (for `klarion rules list`).
func (d *Detector) Rules() []rules.Rule { return d.rules }

// IsBinary sniffs for a NUL byte in the first 8 KiB — the standard
// git-compatible heuristic for binary content.
func IsBinary(data []byte) bool {
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// ScanContent scans a whole blob as lines 1..n. Binary content yields nil.
func (d *Detector) ScanContent(path string, content []byte) []finding.Finding {
	if IsBinary(content) {
		return nil
	}
	raw := bytes.Split(content, []byte("\n"))
	lines := make([]Line, len(raw))
	for i, b := range raw {
		lines[i] = Line{Number: i + 1, Text: strings.TrimSuffix(string(b), "\r")}
	}
	return d.ScanLines(path, lines)
}

// ScanLines runs the full fast pass over the given lines. Context snippets
// are assembled from neighboring entries of the slice, so diff hunks produce
// hunk-local context.
func (d *Detector) ScanLines(path string, lines []Line) []finding.Finding {
	var out []finding.Finding
	seen := make(map[string]bool)

	for i, ln := range lines {
		if len(out) >= maxFindingsPerFile {
			break
		}
		text := ln.Text
		if len(text) > maxLineScanLen {
			text = text[:maxLineScanLen]
		}
		if text == "" || hasAllowMarker(text) {
			continue
		}
		lower := strings.ToLower(text)

		// Stage 1: curated rules.
		var covered []span
		for ri := range d.rules {
			r := &d.rules[ri]
			if !keywordHit(lower, r.Keywords) {
				continue
			}
			locs := r.Regex.FindAllStringSubmatchIndex(text, maxMatchesPerLine)
			for _, m := range locs {
				start, end := m[0], m[1]
				g := r.SecretGroup * 2
				if g+1 < len(m) && m[g] >= 0 {
					start, end = m[g], m[g+1]
				}
				secret := text[start:end]
				if !d.acceptRuleMatch(r, secret) {
					continue
				}
				f := d.newFinding(path, lines, i, ln, r.ID, r.Description, r.Severity, r.Tags, secret, start, end)
				if f == nil || seen[f.Fingerprint] {
					continue
				}
				seen[f.Fingerprint] = true
				covered = append(covered, span{m[0], m[1]})
				out = append(out, *f)
			}
		}

		// Stage 2: generic Rényi-entropy sweep.
		if !d.cfg.Entropy.Enabled {
			continue
		}
		hasKeywordCtx := keywordHit(lower, contextKeywords)
		for _, tok := range tokenize(text) {
			if overlaps(covered, tok.start, tok.end) {
				continue
			}
			secret := tok.text
			if len(secret) < d.cfg.Entropy.MinLength || len(secret) > d.cfg.Entropy.MaxLength {
				continue
			}
			if skip, _ := d.skipGeneric(secret, lower); skip {
				continue
			}
			score := entropy.NormalizedScore(secret)
			threshold := d.cfg.Entropy.ThresholdNoContext
			sev := finding.SeverityMedium
			if hasKeywordCtx {
				threshold = d.cfg.Entropy.Threshold
				sev = finding.SeverityHigh
			}
			if score < threshold {
				continue
			}
			f := d.newFinding(path, lines, i, ln, "generic-high-entropy",
				"High-entropy string (possible secret)", sev, []string{"generic"},
				secret, tok.start, tok.end)
			if f == nil || seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
			out = append(out, *f)
			if len(out) >= maxFindingsPerFile {
				break
			}
		}
	}
	return out
}

// acceptRuleMatch applies per-rule guards: length bounds, allowlist regexes,
// placeholder/stopword filters, entropy floor, and global secret allowlists.
func (d *Detector) acceptRuleMatch(r *rules.Rule, secret string) bool {
	if r.MinLen > 0 && len(secret) < r.MinLen {
		return false
	}
	if r.MaxLen > 0 && len(secret) > r.MaxLen {
		return false
	}
	for _, re := range r.Allowlist {
		if re.MatchString(secret) {
			return false
		}
	}
	if d.cfg.SecretAllowlisted(secret) {
		return false
	}
	if d.isPlaceholder(secret) {
		return false
	}
	if r.Entropy > 0 && entropy.NormalizedScore(secret) < r.Entropy {
		return false
	}
	return true
}

// skipGeneric filters generic-entropy candidates that are almost never
// secrets: UUIDs, content digests in obvious digest context, digit-less
// identifier-shaped tokens, path-like tokens, and placeholders.
func (d *Detector) skipGeneric(secret, lowerLine string) (bool, string) {
	if d.cfg.SecretAllowlisted(secret) {
		return true, "allowlisted"
	}
	if uuidRe.MatchString(secret) {
		return true, "uuid"
	}
	if d.cfg.Entropy.RequireDigit && !hasDigitOrSym(secret) {
		return true, "no-digit"
	}
	if hexRe.MatchString(secret) {
		if len(secret) == 40 && keywordHit(lowerLine, gitShaContext) {
			return true, "git-sha"
		}
		if (len(secret) == 64 || len(secret) == 128) && keywordHit(lowerLine, digestContext) {
			return true, "digest"
		}
	}
	if d.isPlaceholder(secret) {
		return true, "placeholder"
	}
	return false, ""
}

func (d *Detector) isPlaceholder(secret string) bool {
	lower := strings.ToLower(secret)
	for _, w := range d.stopwords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	if maxRepeatRun(secret) >= 5 || maxSequentialRun(secret) >= 6 {
		return true
	}
	// Too few distinct characters for its length → padded/dummy value.
	distinct := distinctCount(secret)
	threshold := len(secret) / 5
	if threshold < 5 {
		threshold = 5
	}
	if threshold > 12 {
		threshold = 12
	}
	return distinct < threshold
}

// newFinding assembles a finding with fingerprint, redaction, entropy scores,
// and a redacted context snippet. Returns nil when the fingerprint is
// permanently allowlisted in the config.
func (d *Detector) newFinding(path string, lines []Line, idx int, ln Line,
	ruleID, desc string, sev finding.Severity, tags []string,
	secret string, start, end int) *finding.Finding {

	f := finding.Finding{
		RuleID:      ruleID,
		Description: desc,
		FilePath:    path,
		Line:        ln.Number,
		Column:      start + 1,
		EndColumn:   end + 1,
		LineText:    ln.Text,
		Secret:      secret,
		Redacted:    finding.Redact(secret),
		Entropy:     entropy.NormalizedScore(secret),
		EntropyBits: entropy.Renyi(secret, d.cfg.Entropy.Alpha),
		Severity:    sev,
		Context:     buildContext(lines, idx),
		Tags:        tags,
	}
	f.Fingerprint = f.ComputeFingerprint()
	if d.cfg.FingerprintAllowlisted(f.Fingerprint) {
		return nil
	}
	return &f
}

// --- helpers ---------------------------------------------------------------

type span struct{ start, end int }

func overlaps(spans []span, start, end int) bool {
	for _, s := range spans {
		if start < s.end && end > s.start {
			return true
		}
	}
	return false
}

type token struct {
	text       string
	start, end int
}

// tokenize extracts candidate runs. The character class deliberately excludes
// '/' and '.' (paths, URLs and domains would otherwise glue into giant
// pseudo-tokens) and '=' (assignment operator); trailing base64 '=' padding
// is re-absorbed after the run.
var tokenRe = regexp.MustCompile(`[A-Za-z0-9+_-]{16,}`)

func tokenize(text string) []token {
	locs := tokenRe.FindAllStringIndex(text, 32)
	toks := make([]token, 0, len(locs))
	for _, l := range locs {
		start, end := l[0], l[1]
		for end < len(text) && text[end] == '=' && end-l[1] < 2 {
			end++
		}
		toks = append(toks, token{text: text[start:end], start: start, end: end})
	}
	return toks
}

func hasAllowMarker(line string) bool {
	return strings.Contains(line, "klarion:allow") || strings.Contains(line, "gitleaks:allow")
}

func keywordHit(lower string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	for _, k := range kws {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

var contextKeywords = []string{
	"secret", "token", "key", "passwd", "password", "pwd", "auth",
	"credential", "bearer", "api", "private", "access", "session",
}

var gitShaContext = []string{"commit", "sha1", "sha ", "ref", "revision", "rev "}

var digestContext = []string{
	"sha256", "sha512", "digest", "integrity", "checksum", "hash", "etag",
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func hasDigitOrSym(s string) bool {
	digits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits++
			if digits >= 2 {
				return true
			}
		}
		if c == '+' || c == '=' {
			return true
		}
	}
	return false
}

func maxRepeatRun(s string) int {
	best, run := 0, 0
	var prev byte
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i] == prev {
			run++
		} else {
			run = 1
		}
		if run > best {
			best = run
		}
		prev = s[i]
	}
	return best
}

func maxSequentialRun(s string) int {
	best, up, down := 0, 1, 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 {
			up++
		} else {
			up = 1
		}
		if s[i] == s[i-1]-1 {
			down++
		} else {
			down = 1
		}
		if up > best {
			best = up
		}
		if down > best {
			best = down
		}
	}
	return best
}

func distinctCount(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}

func buildContext(lines []Line, idx int) string {
	lo := idx - contextRadius
	if lo < 0 {
		lo = 0
	}
	hi := idx + contextRadius
	if hi > len(lines)-1 {
		hi = len(lines) - 1
	}
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		t := lines[i].Text
		if len(t) > maxContextLineLen {
			t = t[:maxContextLineLen] + "…"
		}
		line := fmt.Sprintf("%d: %s\n", lines[i].Number, t)
		if b.Len()+len(line) > maxContextChars {
			break
		}
		b.WriteString(line)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func lowerAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = strings.ToLower(s)
	}
	return out
}
