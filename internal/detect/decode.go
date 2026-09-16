package detect

// Decode, then rescan. A secret inside base64, hex, percent-encoding or \u
// escapes has none of the shape the other stages look for, so encoded spans
// that decode to text are scanned again, recursively, up to
// scan.max_decode_depth.

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/0x1Adi/Klarion/internal/finding"
)

const maxDecodedChars = 500 // decoded text passed to the verifier

var uniEscapeRe = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)

// b64Char marks the base64 and base64url alphabets.
var b64Char = func() (t [256]bool) {
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-" {
		t[c] = true
	}
	return t
}()

// b64Runs returns runs of 16+ base64 characters plus up to two '=' of padding.
// A byte loop: the equivalent regexp cost a quarter of total scan time.
func b64Runs(line string) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(line); i++ {
		if i < len(line) && b64Char[line[i]] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 16 {
			end := i
			for end < len(line) && end-i < 2 && line[end] == '=' {
				end++
			}
			if out = append(out, [2]int{start, end}); len(out) == maxMatchesPerLine {
				break
			}
		}
		start = -1
	}
	return out
}

type decodedSpan struct {
	start, end int
	enc, text  string
}

// decodeSpans returns the encoded spans of line that decode to printable text.
func decodeSpans(line string) []decodedSpan {
	if len(line) < 16 {
		return nil
	}
	var out []decodedSpan
	for _, m := range b64Runs(line) {
		s := line[m[0]:m[1]]
		// Encoded text virtually always carries a digit or '+/='; a run of
		// letters is an identifier, and decoding every one doubled scan time.
		if !strings.ContainsAny(s, "0123456789+/=") {
			continue
		}
		if t, ok := decodeBase64(s); ok {
			out = append(out, decodedSpan{m[0], m[1], "base64", t})
		} else if t, ok := decodeHex(s); ok {
			out = append(out, decodedSpan{m[0], m[1], "hex", t})
		}
	}
	if strings.Count(line, "%") >= 2 {
		if t, err := url.PathUnescape(line); err == nil && t != line {
			if t, ok := printableText([]byte(t)); ok {
				out = append(out, decodedSpan{0, len(line), "percent", t})
			}
		}
	}
	if strings.Contains(line, `\u`) {
		t := uniEscapeRe.ReplaceAllStringFunc(line, func(esc string) string {
			n, _ := strconv.ParseUint(esc[2:], 16, 32)
			return string(rune(n))
		})
		if t != line {
			if t, ok := printableText([]byte(t)); ok {
				out = append(out, decodedSpan{0, len(line), "unicode-escape", t})
			}
		}
	}
	return out
}

func decodeBase64(s string) (string, bool) {
	raw := strings.TrimRight(s, "=")
	if len(raw)%4 == 1 {
		return "", false
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(raw, "-_") {
		if strings.ContainsAny(raw, "+/") {
			return "", false
		}
		enc = base64.RawURLEncoding
	}
	b, err := enc.DecodeString(raw)
	if err != nil {
		return "", false
	}
	return printableText(b)
}

func decodeHex(s string) (string, bool) {
	if len(s) < 16 || len(s)%2 != 0 {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return printableText(b)
}

// printableText accepts decoded bytes only when they read as text: valid UTF-8,
// no control characters, and at least half letters or digits. Random bytes
// almost never pass, so a decoded span is a real signal.
func printableText(b []byte) (string, bool) {
	if len(b) < 6 || !utf8.Valid(b) {
		return "", false
	}
	s := string(b)
	n, alnum := 0, 0
	for _, r := range s {
		n++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
		case !unicode.IsPrint(r):
			return "", false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			alnum++
		}
	}
	return s, alnum*2 >= n
}

// decodeValue annotates a located credential value that is itself encoded
// (FileZilla's <Pass encoding="base64">, .npmrc _auth, a Kubernetes Secret):
// the verifier judges the decoded text, not the encoding.
func decodeValue(v string) string {
	if len(v) < 8 {
		return ""
	}
	if t, ok := decodeBase64(v); ok {
		return "base64: " + clip(t)
	}
	if t, ok := decodeHex(v); ok {
		return "hex: " + clip(t)
	}
	return ""
}

func clip(s string) string {
	if len(s) > maxDecodedChars {
		return s[:maxDecodedChars] + "…"
	}
	return s
}

// decoded rescans the text behind one encoded span and maps every inner finding
// back onto the original line.
func (d *Detector) decoded(path string, lines []Line, idx int, sp decodedSpan, depth int) []finding.Finding {
	parts := strings.Split(sp.text, "\n")
	vl := make([]Line, len(parts))
	for k, p := range parts {
		vl[k] = Line{Number: k + 1, Text: strings.TrimSuffix(p, "\r")}
	}
	inner := d.scanLines(path, vl, depth+1)
	for k := range inner {
		f := &inner[k]
		f.Line = lines[idx].Number
		f.Column, f.EndColumn = sp.start+1, sp.end+1
		f.LineText = lines[idx].Text
		f.Context = buildContext(lines, idx)
		f.Description += " (" + sp.enc + "-decoded)"
		f.Tags = append(append([]string(nil), f.Tags...), "decoded:"+sp.enc)
		if f.Decoded == "" {
			f.Decoded = sp.enc + ": " + clip(sp.text)
		}
	}
	return inner
}
