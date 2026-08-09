package finding

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// keyMaterialExt lists file types whose entire body is one credential: a PEM
// block, a DER blob, a keystore. Detectors fire per line, so one wrapped
// 30-line private key arrives as ~19 separate findings.
var keyMaterialExt = map[string]bool{
	".key": true, ".pem": true, ".crt": true, ".cer": true, ".der": true,
	".p12": true, ".pfx": true, ".jks": true, ".keystore": true,
	".asc": true, ".gpg": true, ".ppk": true, ".pub": true,
}

// keyMaterialBase catches the extensionless conventions (id_rsa, id_ed25519,
// privatekey.txt, private-key-location).
var keyMaterialBase = regexp.MustCompile(`^id_(rsa|dsa|ecdsa|ed25519)|private[-_]?key`)

// testDirCamel matches a camelCase or hyphenated test directory that the flat
// word list would miss: dockerTest, integrationTest, smoke-test, e2e-tests.
//
// It deliberately requires either an uppercase T or a separator before "test".
// A plain suffix check would classify "latest" as a test directory and
// silently suppress real findings under it.
var testDirCamel = regexp.MustCompile(`(^|[a-z0-9])(Test|Tests|IT)$|[-_](test|tests|it)$`)

// testDirWord is the exact-match set of conventional test directory names.
var testDirWord = map[string]bool{
	"test": true, "tests": true, "testing": true, "testdata": true,
	"spec": true, "specs": true, "fixture": true, "fixtures": true,
	"__tests__": true, "e2e": true, "mock": true, "mocks": true, "stubs": true,
	"example": true, "examples": true, "sample": true, "samples": true,
	"demo": true, "demos": true, "bench": true, "benchmark": true, "benchmarks": true,
}

// pemArmor matches any PEM or OpenPGP armor header. Deliberately generic:
// naming the block types missed "-----BEGIN PGP PUBLIC KEY BLOCK-----", which
// alone accounts for 296 of terraform's 367 entropy findings (two embedded
// public keys reported once per base64 line).
//
// Source files embed these as string literals, where no path heuristic can see
// them -- terraform's public_keys.go and crypto_test.go, spring-boot's
// PemSslStoreBundleTests.java. The armor header is a distinctive enough token
// that matching it broadly is safe.
var pemArmor = regexp.MustCompile(`-----BEGIN [A-Z0-9][A-Z0-9 ]*-----`)

// hasArmor reports whether a finding sits in or beside an armored block. The
// detector rarely fires on the armor line itself (it is low entropy), so the
// evidence comes from the surrounding context window of the first few body
// lines -- which is enough to classify the whole run.
func hasArmor(f *Finding) bool {
	return pemArmor.MatchString(f.LineText) || pemArmor.MatchString(f.Context)
}

// minRun is the shortest contiguous run treated as a wrapped block. Two
// adjacent findings are plausibly two real secrets on consecutive lines (an
// .env pair); three or more inside key material is a wrapped body.
const minRun = 3

// maxGap allows one non-matching line inside a run — base64 bodies end with a
// short padded line the entropy rule can miss.
const maxGap = 2

// IsKeyMaterialPath reports whether the path names a file whose whole content
// is a single piece of key material.
func IsKeyMaterialPath(p string) bool {
	q := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	if i := strings.LastIndex(q, "."); i >= 0 && keyMaterialExt[q[i:]] {
		return true
	}
	return keyMaterialBase.MatchString(q)
}

// IsTestPath reports whether the path sits under a test, fixture, example or
// benchmark tree, or is itself a test file.
//
// This is metadata handed to the verifier, never a suppression on its own: a
// production credential committed under test/ is still a leak, and the model
// is the one that decides. Being wrong here costs precision, not recall.
func IsTestPath(p string) bool {
	q := strings.ReplaceAll(p, "\\", "/")
	for _, seg := range strings.Split(path.Dir(q), "/") {
		if seg == "" || seg == "." {
			continue
		}
		if testDirWord[strings.ToLower(seg)] || testDirCamel.MatchString(seg) {
			return true
		}
	}
	base := strings.ToLower(path.Base(q))
	return strings.HasPrefix(base, "test") || strings.HasPrefix(base, "mock") ||
		strings.Contains(base, "_test.") || strings.Contains(base, ".test.") ||
		strings.Contains(base, "-test") || strings.Contains(base, "test-") ||
		strings.Contains(base, ".spec.") || strings.Contains(base, "_spec.")
}

// CollapseKeyBlocks merges runs of same-rule findings on consecutive lines of
// one armored credential into a single finding carrying Occurrences.
//
// A wrapped PEM private key makes every line of its base64 body look like a
// high-entropy string, so one key is reported once per line — measured at 19x
// on spring-boot, 15x worse than the 11x no-dedup behaviour this project
// criticises gitleaks for. Collapsing before adjudication also cuts the model
// calls by the same factor.
//
// A run is eligible only when the file is key material by path, or the run
// itself carries PEM armor. That second condition covers keys embedded as
// string literals in test sources, which no path rule can see. Everything else
// — a .env or YAML holding several distinct secrets on consecutive lines — is
// left alone: merging those would hide real leaks, which costs far more than
// the noise this removes.
func CollapseKeyBlocks(fs []Finding) []Finding {
	type group struct{ file, rule string }
	byGroup := make(map[group][]int)
	// Armor is a file-level property. A context window only spans a few lines,
	// so the header is visible to the first run of a block and invisible to
	// every later one -- which left 112 of terraform's public_keys.go findings
	// uncollapsed when this was evaluated per run.
	armoredFile := make(map[string]bool)
	for i := range fs {
		g := group{fs[i].FilePath, fs[i].RuleID}
		byGroup[g] = append(byGroup[g], i)
		if !armoredFile[fs[i].FilePath] && hasArmor(&fs[i]) {
			armoredFile[fs[i].FilePath] = true
		}
	}

	drop := make(map[int]bool)
	for _, ids := range byGroup {
		sort.Slice(ids, func(a, b int) bool { return fs[ids[a]].Line < fs[ids[b]].Line })
		eligible := IsKeyMaterialPath(fs[ids[0]].FilePath) || armoredFile[fs[ids[0]].FilePath]
		for s := 0; s < len(ids); {
			e := s + 1
			for e < len(ids) && fs[ids[e]].Line-fs[ids[e-1]].Line <= maxGap {
				e++
			}
			// Eligible when the file is key material by path, or holds an
			// armored block anywhere. Everything else -- a .env with several
			// secrets on consecutive lines -- is left alone, because merging
			// those would hide real leaks.
			if n := e - s; n >= minRun && eligible {
				fs[ids[s]].Occurrences = n
				for _, j := range ids[s+1 : e] {
					drop[j] = true
				}
			}
			s = e
		}
	}
	if len(drop) == 0 {
		return fs
	}
	out := make([]Finding, 0, len(fs)-len(drop))
	for i := range fs {
		if !drop[i] {
			out = append(out, fs[i])
		}
	}
	return out
}
