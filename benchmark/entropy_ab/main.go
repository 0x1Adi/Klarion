// Command entropy_ab runs an A/B experiment: for every Stage-2 candidate token
// in the real benchmark corpus, it scores the token with (a) the SHIPPED
// normalized order-2 Rényi (collision) score and (b) a fair normalized Shannon
// (order-1) score, then measures how well each separates real secrets from the
// high-entropy non-secret strings that trip other scanners.
//
// Fairness: both scores are H_alpha(s) / E[H_alpha(uniform random, same length
// & charset)]. Rényi uses the shipped ExpectedCollision normalizer. Shannon
// uses a finite-sample expected-Shannon normalizer (Miller-corrected) so it is
// treated identically — neither is handicapped.
package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0x1Adi/Klarion/internal/entropy"
)

// --- mirror the detector's Stage-2 candidate gates exactly ---

var tokenRe = regexp.MustCompile(`[A-Za-z0-9+_-]{16,}`)
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

const minLen, maxLen = 20, 512

func hasDigitOrSym(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '-' || c == '_' {
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
		prev = s[i]
		if run > best {
			best = run
		}
	}
	return best
}

func maxSequentialRun(s string) int {
	best, run := 0, 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1]+1 || s[i] == s[i-1]-1 {
			run++
		} else {
			run = 1
		}
		if run > best {
			best = run
		}
	}
	if len(s) > 0 && best == 0 {
		best = 1
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

var stopwords = []string{"example", "sample", "placeholder", "changeme", "dummy",
	"xxxx", "test", "your", "0000", "1234", "abcd", "foobar", "secret", "redacted"}

func isPlaceholder(secret string) bool {
	lower := strings.ToLower(secret)
	for _, w := range stopwords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	if maxRepeatRun(secret) >= 5 || maxSequentialRun(secret) >= 6 {
		return true
	}
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

// skipGeneric: true if the detector would drop this generic candidate.
func skipGeneric(secret, lowerLine string) bool {
	if uuidRe.MatchString(secret) {
		return true
	}
	if !hasDigitOrSym(secret) { // RequireDigit=true default
		return true
	}
	if hexRe.MatchString(secret) {
		if len(secret) == 40 && keywordHit(lowerLine, gitShaContext) {
			return true
		}
		if (len(secret) == 64 || len(secret) == 128) && keywordHit(lowerLine, digestContext) {
			return true
		}
	}
	if isPlaceholder(secret) {
		return true
	}
	return false
}

var gitShaContext = []string{"commit", "sha1", "sha ", "ref", "revision", "rev "}
var digestContext = []string{"sha256", "sha512", "digest", "integrity", "checksum", "hash", "etag"}
var contextKeywords = []string{"secret", "token", "key", "passwd", "password", "pwd",
	"auth", "credential", "bearer", "api", "private", "access", "session"}

func keywordHit(lower string, kws []string) bool {
	for _, k := range kws {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// --- fair Shannon normalizer (mirror of entropy.NormalizedScore for alpha=1) ---

// expectedShannon estimates E[Shannon] of a uniform-random length-n string over
// k symbols, with a Miller finite-sample correction so short strings are not
// unfairly compared to the log2(k) asymptote.
func expectedShannon(n, k int) float64 {
	if n < 2 || k < 2 {
		return 0
	}
	occupied := float64(k)
	if float64(n) < occupied { // can't occupy more bins than samples
		occupied = float64(n)
	}
	h := math.Log2(occupied)
	// Miller bias correction: E[Hhat] ≈ H - (K-1)/(2 N ln2)
	h -= (occupied - 1) / (2 * float64(n) * math.Ln2)
	if h <= 0 {
		return 0
	}
	return h
}

func shannonNormalized(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	cs := entropy.Classify(s)
	exp := expectedShannon(len(s), cs.Size)
	if exp <= 0 {
		return 0
	}
	score := entropy.Shannon(s) / exp
	if score < 0 {
		return 0
	}
	if score > 1.25 {
		return 1.25
	}
	return score
}

// --- candidate harvesting ---

type cand struct {
	tok        string
	dataset    string
	file       string
	renyi      float64 // shipped NormalizedScore (alpha=2)
	shannon    float64 // fair normalized alpha=1
	charset    string
	keywordCtx bool
}

func harvest(root, dataset string, out *[]cand) {
	// #nosec G703 -- local dev harness walking a benchmark corpus the operator
	// checked out themselves; there is no untrusted path source here.
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.Contains(p, "/.git/") || strings.Contains(p, "/.leaky-meta/") {
			return nil
		}
		if info.Size() > 1<<20 {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- see the note on the walk above
		if err != nil {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			lower := strings.ToLower(line)
			locs := tokenRe.FindAllStringIndex(line, 64)
			kwctx := keywordHit(lower, contextKeywords)
			for _, l := range locs {
				secret := line[l[0]:l[1]]
				if len(secret) < minLen || len(secret) > maxLen {
					continue
				}
				if skipGeneric(secret, lower) {
					continue
				}
				*out = append(*out, cand{
					tok: secret, dataset: dataset, file: filepath.Base(p),
					renyi: entropy.NormalizedScore(secret), shannon: shannonNormalized(secret),
					charset: entropy.Classify(secret).Name, keywordCtx: kwctx,
				})
			}
		}
		return nil
	})
}

// AUC via rank statistic (prob a random positive scores above a random negative).
func auc(pos, neg []float64) float64 {
	type sv struct {
		v   float64
		lbl int
	}
	all := make([]sv, 0, len(pos)+len(neg))
	for _, v := range pos {
		all = append(all, sv{v, 1})
	}
	for _, v := range neg {
		all = append(all, sv{v, 0})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })
	// assign ranks with tie handling (average ranks)
	i := 0
	var rankSumPos float64
	for i < len(all) {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		avgRank := float64(i+j+1) / 2.0 // ranks are 1-based
		for k := i; k < j; k++ {
			if all[k].lbl == 1 {
				rankSumPos += avgRank
			}
		}
		i = j
	}
	nP, nN := float64(len(pos)), float64(len(neg))
	if nP == 0 || nN == 0 {
		return math.NaN()
	}
	return (rankSumPos - nP*(nP+1)/2) / (nP * nN)
}

// fpAtRecall: given positive & negative scores, find the threshold that keeps
// `recall` fraction of positives, and report how many negatives (FPs) survive.
func fpAtRecall(pos, neg []float64, recall float64) (thr float64, fp int) {
	sp := append([]float64(nil), pos...)
	sort.Float64s(sp)
	// keep top `recall` of positives => threshold at the (1-recall) quantile
	idx := int(math.Floor((1 - recall) * float64(len(sp))))
	if idx >= len(sp) {
		idx = len(sp) - 1
	}
	thr = sp[idx]
	for _, v := range neg {
		if v >= thr {
			fp++
		}
	}
	return thr, fp
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func main() {
	// Corpora are fetched, not vendored (benchmark/fetch-datasets.sh). Default
	// is relative to this command's directory; KLARION_DATASETS overrides it.
	base := os.Getenv("KLARION_DATASETS")
	if base == "" {
		base = filepath.Join("..", "datasets")
	}
	var all []cand
	harvest(filepath.Join(base, "leaky-repo"), "leaky", &all)
	harvest(filepath.Join(base, "fp-flask"), "flask", &all)
	harvest(filepath.Join(base, "fp-rails"), "rails", &all)

	// Ground-truth labeling.
	// NEGATIVES: every candidate from the clean real-world repos (flask, rails).
	//   Prior benchmark established these repos contain 0 real secrets, so every
	//   high-entropy candidate here is a false positive — exactly what we want
	//   entropy to reject.
	// POSITIVES: real secret tokens. We take leaky-repo candidates whose line has
	//   a secret-ish keyword context (the true credential lines) AND, separately,
	//   a synthetic set of real-looking random keys (what generated API keys are).
	var negR, negS []float64 // clean-repo false positives
	var posR, posS []float64 // real leaky secrets (keyword-context lines)
	leakyAll := 0
	for _, c := range all {
		switch c.dataset {
		case "flask", "rails":
			negR = append(negR, c.renyi)
			negS = append(negS, c.shannon)
		case "leaky":
			leakyAll++
			if c.keywordCtx {
				posR = append(posR, c.renyi)
				posS = append(posS, c.shannon)
			}
		}
	}

	fmt.Println("=== Corpus candidate counts (Stage-2 gates applied) ===")
	fmt.Printf("leaky candidates:            %d (keyword-context positives: %d)\n", leakyAll, len(posR))
	fmt.Printf("clean-repo negatives (FPs):  %d\n", len(negR))

	fmt.Println("\n=== Mean normalized score by group ===")
	fmt.Printf("%-28s  Renyi(a=2)   Shannon(a=1)\n", "")
	fmt.Printf("%-28s  %.4f       %.4f\n", "real secrets (leaky/kw)", mean(posR), mean(posS))
	fmt.Printf("%-28s  %.4f       %.4f\n", "clean-repo FP strings", mean(negR), mean(negS))
	fmt.Printf("%-28s  %.4f       %.4f\n", "separation (pos-neg)", mean(posR)-mean(negR), mean(posS)-mean(negS))

	fmt.Println("\n=== AUC: real-secret vs clean-FP discrimination (higher=better) ===")
	fmt.Printf("Renyi   (alpha=2): %.4f\n", auc(posR, negR))
	fmt.Printf("Shannon (alpha=1): %.4f\n", auc(posS, negS))

	fmt.Println("\n=== FPs admitted at matched recall on clean repos ===")
	for _, rec := range []float64{1.0, 0.95, 0.90} {
		_, fpR := fpAtRecall(posR, negR, rec)
		_, fpS := fpAtRecall(posS, negS, rec)
		fmt.Printf("recall=%.0f%%:  Renyi FP=%-4d  Shannon FP=%-4d  (of %d clean candidates)\n",
			rec*100, fpR, fpS, len(negR))
	}

	// TOKEN-COST question: at matched recall on real secrets, how many candidates
	// does each metric hand to the AI? Load ~= candidates crossing threshold.
	// negatives dominate, so load is driven by FP candidates. Report the ratio =
	// how many more AI tokens Shannon would cost to catch the SAME secrets.
	fmt.Println("\n=== AI candidate load at MATCHED recall (fair token-cost comparison) ===")
	fmt.Printf("%-10s  %-22s  %-22s  %s\n", "recall", "Renyi load (kept)", "Shannon load (kept)", "Shannon/Renyi")
	for _, rec := range []float64{0.50, 0.60, 0.70, 0.80, 0.90, 0.95, 1.00} {
		tR, fR := fpAtRecall(posR, negR, rec)
		tS, fS := fpAtRecall(posS, negS, rec)
		// load = kept positives (= rec*len(pos)) + kept negatives(FP). AI sees all crossings.
		loadR := int(rec*float64(len(posR))) + fR
		loadS := int(rec*float64(len(posS))) + fS
		fmt.Printf("%-10.0f  thr=%.3f -> %-11d  thr=%.3f -> %-11d  %.2fx\n",
			rec*100, tR, loadR, tS, loadS, float64(loadS)/float64(loadR))
	}

	// Synthetic controlled test: real random keys (positives) vs structured
	// high-entropy strings that fool Shannon (negatives). Deterministic PRNG.
	fmt.Println("\n=== Synthetic controlled test (random keys vs structured hi-entropy) ===")
	runSynthetic()

	// Threshold crossover: at the SHIPPED thresholds, how many clean-repo
	// candidates cross under each scorer (all are FPs)?
	fmt.Println("\n=== Shipped-threshold FP count on clean repos (all crossings are FPs) ===")
	for _, c := range []struct {
		name string
		thr  float64
	}{{"no-context (0.95)", 0.95}, {"keyword-context (0.88)", 0.88}} {
		var fr, fs int
		for _, c2 := range all {
			if c2.dataset == "flask" || c2.dataset == "rails" {
				if c2.renyi >= c.thr {
					fr++
				}
				if c2.shannon >= c.thr {
					fs++
				}
			}
		}
		fmt.Printf("thr %-24s  Renyi crosses=%-4d  Shannon crosses=%-4d\n", c.name, fr, fs)
	}
}

// deterministic LCG so results are reproducible without Math.random.
type lcg struct{ s uint64 }

func (l *lcg) next() uint64 { l.s = l.s*6364136223846793005 + 1442695040888963407; return l.s }
func (l *lcg) intn(n int) int {
	if n <= 0 {
		return 0
	}
	// #nosec G115 -- n is positive here and the result is < n, so both
	// conversions are in range.
	return int(l.next() >> 33 % uint64(n))
}

func runSynthetic() {
	rng := &lcg{s: 0x1234567890abcdef}
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// positives: uniform-random base64 keys, length 32-44 (real API keys)
	var posR, posS []float64
	for i := 0; i < 4000; i++ {
		n := 32 + rng.intn(13)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteByte(b64[rng.intn(64)])
		}
		s := sb.String()
		posR = append(posR, entropy.NormalizedScore(s))
		posS = append(posS, shannonNormalized(s))
	}
	// negatives: structured high-entropy strings that fool Shannon but have
	// skewed byte distributions — base64 of english-like text, hex digests with
	// digit-skew, and camelCase-ish long identifiers with a digit.
	words := []string{"the", "config", "handler", "request", "response", "service",
		"manager", "client", "server", "session", "context", "provider", "default",
		"internal", "package", "version", "component", "template", "resource"}
	var negR, negS []float64
	for i := 0; i < 4000; i++ {
		mode := rng.intn(3)
		var s string
		switch mode {
		case 0: // long lowerCamel identifier + trailing digits (skewed toward lowercase)
			var sb strings.Builder
			for sb.Len() < 28 {
				w := words[rng.intn(len(words))]
				sb.WriteString(strings.Title(w))
			}
			sb.WriteString(fmt.Sprintf("%d", rng.intn(1000)))
			s = sb.String()
		case 1: // hex digest but with heavy digit skew (dates/ids embedded)
			const hexd = "0123456789abcdef"
			var sb strings.Builder
			for j := 0; j < 40; j++ {
				// bias: 60% digits, 40% a-f  -> skewed vs uniform hex
				if rng.intn(10) < 6 {
					sb.WriteByte("0123456789"[rng.intn(10)])
				} else {
					sb.WriteByte(hexd[10+rng.intn(6)])
				}
			}
			s = sb.String()
		default: // base64 of repeated-ish structured text (low per-symbol surprise)
			var sb strings.Builder
			for sb.Len() < 40 {
				sb.WriteString(words[rng.intn(4)]) // only 4 words -> skewed
				sb.WriteString("123")
			}
			s = sb.String()
			if len(s) > 44 {
				s = s[:44]
			}
		}
		if len(s) < minLen || skipGeneric(s, "") {
			continue
		}
		negR = append(negR, entropy.NormalizedScore(s))
		negS = append(negS, shannonNormalized(s))
	}
	fmt.Printf("positives(random keys)=%d  negatives(structured)=%d\n", len(posR), len(negR))
	fmt.Printf("mean pos:  Renyi=%.4f  Shannon=%.4f\n", mean(posR), mean(posS))
	fmt.Printf("mean neg:  Renyi=%.4f  Shannon=%.4f\n", mean(negR), mean(negS))
	fmt.Printf("AUC:       Renyi=%.4f  Shannon=%.4f\n", auc(posR, negR), auc(posS, negS))
	for _, rec := range []float64{1.0, 0.99, 0.95} {
		_, fpR := fpAtRecall(posR, negR, rec)
		_, fpS := fpAtRecall(posS, negS, rec)
		fmt.Printf("recall=%.0f%%:  Renyi FP=%-4d  Shannon FP=%-4d  (of %d)\n",
			rec*100, fpR, fpS, len(negR))
	}
}
