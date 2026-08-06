package detect

// TestEntropyModelSweep is a research harness (run explicitly) that answers
// "which entropy model best separates real secrets from the high-entropy code
// artifacts that cause false positives?" It reuses the REAL detector gates
// (tokenize, skipGeneric) so the candidate population is production-faithful,
// and normalizes EVERY model with one identical Monte-Carlo method so we are
// comparing models, not normalizers (the confound that faked a Renyi win last
// round). Run:
//
//	go test ./internal/detect/ -run TestEntropyModelSweep -v -timeout 300s
//
// It never asserts; it prints a ranked table.

import (
	"bytes"
	"compress/flate"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/entropy"
)

// datasetBase locates the benchmark corpora, which are fetched rather than
// vendored (see benchmark/fetch-datasets.sh). Default is relative to this
// package; KLARION_DATASETS overrides it for out-of-tree checkouts.
var datasetBase = func() string {
	if p := os.Getenv("KLARION_DATASETS"); p != "" {
		return p
	}
	return filepath.Join("..", "..", "benchmark", "datasets")
}()

// ---------- raw statistics (bits) over a token ----------

func renyiBits(s string, alpha float64) float64 { return entropy.Renyi(s, alpha) }

func minEntropyBits(s string) float64 { // Renyi alpha -> infinity
	if len(s) < 2 {
		return 0
	}
	var counts [256]int
	mx := 0
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
		if counts[s[i]] > mx {
			mx = counts[s[i]]
		}
	}
	return -math.Log2(float64(mx) / float64(len(s)))
}

// bigramCondBits: H(next | prev), the order-1 Markov conditional entropy.
func bigramCondBits(s string) float64 {
	if len(s) < 3 {
		return 0
	}
	type pair struct{ a, b byte }
	bi := map[pair]int{}
	uni := map[byte]int{}
	for i := 0; i+1 < len(s); i++ {
		bi[pair{s[i], s[i+1]}]++
		uni[s[i]]++
	}
	N := float64(len(s) - 1)
	var h float64
	for p, c := range bi {
		pPrev := float64(uni[p.a]) / N
		pCond := float64(c) / float64(uni[p.a])
		h += pPrev * (-pCond * math.Log2(pCond))
	}
	return h
}

// trigramCondBits: H(next | prev2), order-2 Markov conditional entropy.
func trigramCondBits(s string) float64 {
	if len(s) < 4 {
		return 0
	}
	type tri struct{ a, b, c byte }
	type duo struct{ a, b byte }
	tr := map[tri]int{}
	ctx := map[duo]int{}
	for i := 0; i+2 < len(s); i++ {
		tr[tri{s[i], s[i+1], s[i+2]}]++
		ctx[duo{s[i], s[i+1]}]++
	}
	N := float64(len(s) - 2)
	var h float64
	for t, c := range tr {
		pCtx := float64(ctx[duo{t.a, t.b}]) / N
		pCond := float64(c) / float64(ctx[duo{t.a, t.b}])
		h += pCtx * (-pCond * math.Log2(pCond))
	}
	return h
}

// compressionRatio: flate-compressed length / raw length. ~1.0 = incompressible
// (random-looking); <1 = structured/repetitive. Not MC-normalized (already a
// length-relative ratio); AUC is scale-invariant.
func compressionRatio(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	w.Write([]byte(s))
	w.Close()
	return float64(buf.Len()) / float64(len(s))
}

// ---------- Monte-Carlo normalization (identical method for every model) ----------

const mcSamples = 400

var mcCache = map[string]float64{}

// expected returns E[stat(uniform random string of length nBucket over k
// symbols)], memoized. Deterministic: seed derives from (id,nBucket,k), so the
// value is independent of evaluation order.
func expected(id string, statBits func(string) float64, n, k int) float64 {
	nb := (n / 8) * 8
	if nb < 16 {
		nb = 16
	}
	if nb > 512 {
		nb = 512
	}
	if k < 2 {
		k = 2
	}
	key := fmt.Sprintf("%s|%d|%d", id, nb, k)
	if v, ok := mcCache[key]; ok {
		return v
	}
	h := fnv.New64a()
	h.Write([]byte(key))
	rng := rand.New(rand.NewSource(int64(h.Sum64())))
	// 94 distinct printable ASCII symbols (33..126) — covers max charset size.
	alpha := make([]byte, 0, 94)
	for c := byte(33); c <= 126; c++ {
		alpha = append(alpha, c)
	}
	if k > len(alpha) {
		k = len(alpha)
	}
	var sum float64
	buf := make([]byte, nb)
	for i := 0; i < mcSamples; i++ {
		for j := 0; j < nb; j++ {
			buf[j] = alpha[rng.Intn(k)]
		}
		sum += statBits(string(buf))
	}
	v := sum / float64(mcSamples)
	mcCache[key] = v
	return v
}

// normScore = stat(token) / E[stat(uniform, same length & charset)], clamped.
func normScore(id string, statBits func(string) float64, s string) float64 {
	if len(s) < 2 {
		return 0
	}
	k := entropy.Classify(s).Size
	e := expected(id, statBits, len(s), k)
	if e <= 0 {
		return 0
	}
	v := statBits(s) / e
	if v < 0 {
		v = 0
	}
	if v > 1.5 {
		v = 1.5
	}
	return v
}

// ---------- scorer registry ----------

type scorer struct {
	name string
	fn   func(string) float64
}

func buildScorers() []scorer {
	mk := func(id string, stat func(string) float64) func(string) float64 {
		return func(s string) float64 { return normScore(id, stat, s) }
	}
	return []scorer{
		{"Hartley (a=0)", mk("h0", func(s string) float64 { return renyiBits(s, 1e-6) })},
		{"Renyi a=0.5", mk("r05", func(s string) float64 { return renyiBits(s, 0.5) })},
		{"Shannon (a=1)", mk("shan", func(s string) float64 { return renyiBits(s, 1) })},
		{"Renyi a=1.5", mk("r15", func(s string) float64 { return renyiBits(s, 1.5) })},
		{"Collision a=2 [SHIPPED]", mk("r2", func(s string) float64 { return renyiBits(s, 2) })},
		{"Renyi a=3", mk("r3", func(s string) float64 { return renyiBits(s, 3) })},
		{"Renyi a=4", mk("r4", func(s string) float64 { return renyiBits(s, 4) })},
		{"Min-entropy (a=inf)", mk("rinf", minEntropyBits)},
		{"Bigram cond H", mk("bi", bigramCondBits)},
		{"Trigram cond H", mk("tri", trigramCondBits)},
		{"Compression ratio", compressionRatio},
		// composites (unfitted, illustrative ceiling)
		{"Collision x Bigram", func(s string) float64 {
			return normScore("r2", func(x string) float64 { return renyiBits(x, 2) }, s) *
				normScore("bi", bigramCondBits, s)
		}},
		{"Collision x Compress", func(s string) float64 {
			return normScore("r2", func(x string) float64 { return renyiBits(x, 2) }, s) *
				compressionRatio(s)
		}},
		{"Bigram x Compress", func(s string) float64 {
			return normScore("bi", bigramCondBits, s) * compressionRatio(s)
		}},
	}
}

// ---------- corpus ----------

func harvestNegatives(t *testing.T, d *Detector) []string {
	var out []string
	for _, ds := range []string{"fp-flask", "fp-rails"} {
		root := filepath.Join(datasetBase, ds)
		filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || strings.Contains(p, "/.git/") || info.Size() > 1<<20 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for _, line := range strings.Split(string(b), "\n") {
				lower := strings.ToLower(line)
				for _, tok := range tokenize(line) {
					s := tok.text
					if len(s) < 20 || len(s) > 512 {
						continue
					}
					if skip, _ := d.skipGeneric(s, lower); skip {
						continue
					}
					out = append(out, s)
				}
			}
			return nil
		})
	}
	return out
}

// realPositives: secrets confirmed by Stage-1 regex rules in leaky-repo.
func harvestRealPositives(t *testing.T, d *Detector) []string {
	seen := map[string]bool{}
	var out []string
	root := filepath.Join(datasetBase, "leaky-repo")
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.Contains(p, "/.git/") || strings.Contains(p, "/.leaky-meta/") || info.Size() > 1<<20 {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		for _, f := range d.ScanContent(rel, b) {
			if f.RuleID == "generic-high-entropy" {
				continue // keep only regex-confirmed real secrets as clean positives
			}
			s := f.Secret
			if len(s) < 20 || len(s) > 512 || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		return nil
	})
	return out
}

// syntheticPositives: realistic generated secrets (what real keys look like:
// near-uniform over their charset), spanning the charset mix real secrets use.
func syntheticPositives(n int) []string {
	rng := rand.New(rand.NewSource(0xC0FFEE))
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const b62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	const hexd = "0123456789abcdef"
	const upalnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	gen := func(cs string, ln int) string {
		var sb strings.Builder
		for i := 0; i < ln; i++ {
			sb.WriteByte(cs[rng.Intn(len(cs))])
		}
		return sb.String()
	}
	var out []string
	for i := 0; i < n; i++ {
		switch rng.Intn(6) {
		case 0:
			out = append(out, gen(b64, 32+rng.Intn(13))) // generic base64 key
		case 1:
			out = append(out, gen(hexd, []int{32, 40, 64}[rng.Intn(3)])) // hex api key
		case 2:
			out = append(out, gen(b62, 24+rng.Intn(16))) // alnum token
		case 3:
			out = append(out, "AKIA"+gen(upalnum, 16)) // aws-style
		case 4:
			out = append(out, "ghp_"+gen(b62, 36)) // github-style
		case 5:
			out = append(out, gen(b64, 40)+"==") // padded base64 secret
		}
	}
	return out
}

// ---------- metrics ----------

func auc(pos, neg []float64) float64 {
	type sv struct {
		v float64
		l int
	}
	all := make([]sv, 0, len(pos)+len(neg))
	for _, v := range pos {
		all = append(all, sv{v, 1})
	}
	for _, v := range neg {
		all = append(all, sv{v, 0})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v < all[j].v })
	i := 0
	var rankSumPos float64
	for i < len(all) {
		j := i
		for j < len(all) && all[j].v == all[i].v {
			j++
		}
		avg := float64(i+j+1) / 2.0
		for k := i; k < j; k++ {
			if all[k].l == 1 {
				rankSumPos += avg
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

// bootstrapCI returns the 2.5/97.5 percentile AUC over B resamples.
func bootstrapCI(pos, neg []float64, B int) (lo, hi float64) {
	rng := rand.New(rand.NewSource(1))
	negCap := len(neg)
	if negCap > 4000 {
		negCap = 4000
	}
	aucs := make([]float64, 0, B)
	bp := make([]float64, len(pos))
	bn := make([]float64, negCap)
	for b := 0; b < B; b++ {
		for i := range bp {
			bp[i] = pos[rng.Intn(len(pos))]
		}
		for i := range bn {
			bn[i] = neg[rng.Intn(len(neg))]
		}
		aucs = append(aucs, auc(bp, bn))
	}
	sort.Float64s(aucs)
	return aucs[int(0.025*float64(B))], aucs[int(0.975*float64(B))]
}

func fpAtRecall(pos, neg []float64, recall float64) int {
	// No positives means no threshold to derive; report 0 rather than
	// indexing an empty slice.
	if len(pos) == 0 {
		return 0
	}
	sp := append([]float64(nil), pos...)
	sort.Float64s(sp)
	idx := int(math.Floor((1 - recall) * float64(len(sp))))
	if idx >= len(sp) {
		idx = len(sp) - 1
	}
	if idx < 0 {
		idx = 0
	}
	thr := sp[idx]
	fp := 0
	for _, v := range neg {
		if v >= thr {
			fp++
		}
	}
	return fp
}

func charsetHist(toks []string) map[string]int {
	m := map[string]int{}
	for _, s := range toks {
		m[entropy.Classify(s).Name]++
	}
	return m
}

func TestEntropyModelSweep(t *testing.T) {
	d, err := New(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	neg := harvestNegatives(t, d)
	realPos := harvestRealPositives(t, d)
	synPos := syntheticPositives(3000)

	// benchmark/datasets/ is gitignored on purpose — the corpora are large
	// third-party checkouts, not repo content — so a CI runner harvests
	// nothing. With no negatives or real positives there is no ranking to do,
	// and fpAtRecall indexes an empty slice and panics. This is an offline
	// research sweep, not a correctness gate, so skip instead of failing.
	if len(neg) == 0 || len(realPos) == 0 {
		t.Skipf("entropy model sweep needs the benchmark corpus "+
			"(negatives=%d, real positives=%d); populate benchmark/datasets/ to run it",
			len(neg), len(realPos))
	}

	fmt.Printf("\nCORPUS: negatives(clean flask+rails candidates)=%d  real-secret positives=%d  synthetic positives=%d\n",
		len(neg), len(realPos), len(synPos))
	fmt.Printf("charset(neg)=%v\ncharset(realPos)=%v\ncharset(synPos)=%v\n\n",
		charsetHist(neg), charsetHist(realPos), charsetHist(synPos))

	scorers := buildScorers()
	// precompute scores once per token per scorer
	type row struct {
		name              string
		aucReal, aucSyn   float64
		loReal, hiReal    float64
		loSyn, hiSyn      float64
		fpReal95, fpSyn95 int
	}
	negScores := make(map[string][]float64)
	realScores := make(map[string][]float64)
	synScores := make(map[string][]float64)
	for _, sc := range scorers {
		ns := make([]float64, len(neg))
		for i, s := range neg {
			ns[i] = sc.fn(s)
		}
		negScores[sc.name] = ns
		rs := make([]float64, len(realPos))
		for i, s := range realPos {
			rs[i] = sc.fn(s)
		}
		realScores[sc.name] = rs
		ss := make([]float64, len(synPos))
		for i, s := range synPos {
			ss[i] = sc.fn(s)
		}
		synScores[sc.name] = ss
	}

	var rows []row
	for _, sc := range scorers {
		ng := negScores[sc.name]
		rp := realScores[sc.name]
		sp := synScores[sc.name]
		loR, hiR := bootstrapCI(rp, ng, 400)
		loS, hiS := bootstrapCI(sp, ng, 400)
		rows = append(rows, row{
			name:    sc.name,
			aucReal: auc(rp, ng), aucSyn: auc(sp, ng),
			loReal: loR, hiReal: hiR, loSyn: loS, hiSyn: hiS,
			fpReal95: fpAtRecall(rp, ng, 0.95), fpSyn95: fpAtRecall(sp, ng, 0.95),
		})
	}
	// rank by mean of the two AUCs
	sort.Slice(rows, func(i, j int) bool {
		return (rows[i].aucReal + rows[i].aucSyn) > (rows[j].aucReal + rows[j].aucSyn)
	})

	fmt.Printf("%-26s | %-22s | %-22s | %s\n", "MODEL", "AUC real (95% CI)", "AUC synth (95% CI)", "FP@95%recall r/s")
	fmt.Println(strings.Repeat("-", 100))
	for _, r := range rows {
		fmt.Printf("%-26s | %.3f [%.3f,%.3f]   | %.3f [%.3f,%.3f]   | %d / %d\n",
			r.name, r.aucReal, r.loReal, r.hiReal, r.aucSyn, r.loSyn, r.hiSyn, r.fpReal95, r.fpSyn95)
	}
	fmt.Printf("\n(higher AUC = better secret/FP separation; FP counts out of %d clean candidates)\n", len(neg))

	// Charset-confound check: AUC of shipped collision within the two biggest
	// negative charsets, using synthetic positives restricted to same charset.
	fmt.Println("\n=== charset-stratified sanity (shipped Collision a=2) ===")
	for _, csName := range []string{"hex", "base64", "alphanum", "lowernum"} {
		var p, n []float64
		coll := func(s string) float64 { return normScore("r2", func(x string) float64 { return renyiBits(x, 2) }, s) }
		for _, s := range synPos {
			if entropy.Classify(s).Name == csName {
				p = append(p, coll(s))
			}
		}
		for _, s := range neg {
			if entropy.Classify(s).Name == csName {
				n = append(n, coll(s))
			}
		}
		if len(p) > 5 && len(n) > 5 {
			fmt.Printf("  charset=%-9s  AUC=%.3f  (pos=%d neg=%d)\n", csName, auc(p, n), len(p), len(n))
		}
	}
}
