# Klarion comparative benchmark — real-data study vs. 4 secret scanners

**Date:** 2026-07-09 · **Platform:** macOS arm64 (Darwin 25.2.0) · **Klarion:** dev build (claude-cli AI verifier, haiku)
**Compared:** gitleaks 8.30.0 · trufflehog 3.93.5 · detect-secrets 1.5.0 (Yelp) · ripsecrets 0.1.11

> **On the raw output.** Verbatim scanner output is not committed. It quotes leaky-repo's
> credentials line by line, and that corpus is third party, so publishing it here would just make
> this repo a second copy of those secrets. What ships is the derived evidence: `results/accuracy.json`,
> `results/timing-*.json` and `results/study.json`. Regenerate the raw output yourself with
> `benchmark/fetch-datasets.sh` followed by `benchmark/harness/run_benchmark.py`.
>
> **On the file names.** This run happened while the project was still called Kavach, so the
> regenerated files are named `kavach-*.out` and carry `"tool": "kavach"` inside wherever the
> committed numbers reference them. Kavach and Klarion are the same tool, same commit. Re-running
> the harness today writes `klarion-*.out` instead.

## TL;DR

- **Precision:** Klarion-AI is the only tool with **zero findings on clean real-world corpora** (flask + rails, 54 MB, 3,700+ files). Every other tool reports 9–247 noise findings there. This is a property of the **AI configuration**, which is the only supported way to run Klarion. The §10 structural suppressors also bring the no-AI path to 0 *on these two corpora*, but that result does not generalize — see [§12](#12-addendum--the-no-ai-path-does-not-generalize).
- **Recall:** On the leaky-repo ground truth, Klarion-AI detects 43% of risk files with **perfect file precision (1.00)** — second-best recall behind detect-secrets (55%), which pays for it with 247 clean-corpus false positives.
- **F1 (leaky, file level):** Klarion-no-AI 0.74 (after the [§10](#10-addendum--structural-suppressors-for-the-no-ai-path) fixes) > detect-secrets 0.70 > **Klarion-AI 0.60** > gitleaks 0.47 > trufflehog 0.32 > ripsecrets 0.17. The no-AI row is **measured on corpora that its own suppressors were tuned against** and is reported for diagnostic honesty, not as a recommendation; [§12](#12-addendum--the-no-ai-path-does-not-generalize) shows it collapsing on unseen repositories. Among shippable configurations, Klarion-AI has the best precision/recall balance in the study.
- **Speed:** Klarion's scan stage is the fastest of all five tools (12.9 ms on leaky-repo, 0.61 s on rails — 2–4.6× faster than the runner-up). AI adjudication adds minutes when routed through `claude -p` (CLI startup dominates); with a real API key and parallel batches this is seconds.
- The benchmark surfaced and fixed **two real Klarion bugs** (verdict misassignment when the cache dedups a batch; model under-filling batch verdicts) and produced a ranked detection-gap roadmap worth ~+19 points of recall.

---

## 1. Methodology

### Datasets (all real data)

| Corpus | What it is | Role |
|---|---|---|
| [leaky-repo](https://github.com/Plazmaz/leaky-repo) | Community-standard benchmark: 44 files of real-format secrets (.npmrc, .ssh keys, wp-config.php, .env, …) with an official per-file ground truth (`.leaky-meta/secrets.csv`: 96 "risk" + 76 "informative" values; 42 files carry risk) | Recall / accuracy |
| flask @ HEAD (3.2 MB) | Real OSS repo, shallow clone | False-positive corpus |
| rails @ HEAD (51 MB) | Real OSS repo, shallow clone | False-positive corpus + speed at scale |
| leaky-repo git history (25 commits) | Real multi-year commit history | Git-history mode comparison |

All tools scanned identical working trees (`.git` and `.leaky-meta` removed) in offline mode for parity: trufflehog with `--no-verification`, detect-secrets `--all-files`, Klarion with an explicit config (its auto-discovered dogfood `.klarion.toml` would otherwise allowlist paths — found and fixed during setup).

### Scoring

Mirrors leaky-repo's official `benchmark.py` (per-file expected counts, capped find coverage, file coverage) plus file-level precision/recall/F1 against **risk files** (files with ≥1 risk secret). An independent adversarial agent re-parsed every raw output and re-implemented the scoring from scratch: **zero diffs across all tools and datasets**.

Clean-corpus findings were individually reviewed by auditor agents (94 Klarion candidates, 33 gitleaks, 9 trufflehog, 61 ripsecrets: 100% reviewed; detect-secrets: stratified 73/247 sample), each audit adversarially re-verified by a second agent reading the flagged lines.

### Klarion configurations

- **Klarion-AI (primary):** two-stage pipeline — deterministic detection (83 rules + Rényi entropy) then AI adjudication of every candidate via the new `claude-cli` provider (`claude -p --model haiku`, batches of 10, verdict-refill on model under-fill, retry on transient CLI failure). `filter_false_positives = true`, `min_confidence = 0.6`.
- **Klarion candidates (no AI):** detection stage + offline heuristic only. Shown to expose the pipeline's recall ceiling. **This is not a product configuration** and must not be quoted as one — see [§12](#12-addendum--the-no-ai-path-does-not-generalize).

---

## 2. Accuracy on leaky-repo (44 GT files, 42 with risk secrets)

| Tool | Findings | File coverage | Find coverage | Risk-file recall | File precision | F1 |
|---|---|---|---|---|---|---|
| **Klarion-AI** | 72 | 40.9% | 18.3% | **0.43** | **1.00** | **0.60** |
| Klarion candidates (no AI) | 98 | 45.5% | 22.3% | 0.43 | 0.90 | 0.58 |
| Klarion no AI, *after* the §10 fixes ([§10](#10-addendum--structural-suppressors-for-the-no-ai-path)) | 113 | — | — | **0.62** | **0.93** | **0.74** |
| gitleaks | 22 | 29.5% | 12.6% | 0.31 | 1.00 | 0.47 |
| trufflehog | 12 | 18.2% | 6.9% | 0.19 | 1.00 | 0.32 |
| detect-secrets | 46 | **54.5%** | **24.0%** | **0.55** | 0.96 | **0.70** |
| ripsecrets | 4 | 9.1% | 2.3% | 0.10 | 1.00 | 0.17 |

Notes:
- detect-secrets' recall lead comes from breadth (27 plugins incl. keyword + entropy detectors), but see §3 for what that costs on real repos.
- trufflehog's low score is by design: ~1,000 provider-specific detectors aimed at *verifiable* credentials; leaky-repo's generic passwords/configs aren't its target.
- ripsecrets **never scans hidden files/dot-directories** (v0.1.11, no flag to change it) — most leaky-repo files are dotfiles. On visible-file corpora it is stronger than this number suggests.
- Every file flagged by every tool was a GT file (no out-of-GT noise on leaky-repo itself).

### What the AI layer changed (vs. the same detector with the offline heuristic)

Claude adjudicated all 98 candidates: **recovered 7 risk files** the heuristic wrongly suppressed (`.docker/.dockercfg`, `.docker/config.json`, `.npmrc`, `.vscode/sftp.json`, `deployment-config.json`, `hub`, `sftp-config.json` — real credential formats the heuristic's "example/test context" rule killed), and **suppressed 9 files** the heuristic kept — including correct calls (`.ssh/id_rsa.pub` is a public key; `high-entropy-misc.txt` carries no risk secrets; `db/dump.sql`/`.htpasswd` contain bcrypt-hashed passwords, not recoverable credentials) alongside real over-suppressions on the benchmark's terms (`web/var/www/.env`, `db/mongoid.yml`, `web/ruby/secrets.yml`). Net: equal recall, precision → 1.00, and every kept finding carries an explicit `secret` verdict with a reason.

---

## 3. Clean-corpus noise (real repos, should be ~zero)

| Tool | flask findings | rails findings | Audited composition (rails+flask) |
|---|---|---|---|
| **Klarion-AI** | **0** | **0** | all 99 candidates adjudicated false-positive |
| Klarion candidates | 6 | 93 | 4 fixtures / 25 placeholders / 65 noise / **0 possibly real** |
| Klarion no AI, *after* the fix ([§10](#10-addendum--structural-suppressors-for-the-no-ai-path)) | 0 | 0 | all 99 suppressed structurally — but tuned *on these corpora*; see [§12](#12-addendum--the-no-ai-path-does-not-generalize) |
| gitleaks | 6 | 27 | 19 fixtures / 13 placeholders / 1 noise / 0 real |
| trufflehog | 0 | 9 | 1 fixture / 7 placeholders / 1 noise / 0 real |
| detect-secrets | 23 | 224 | (73 sampled) 9 fixtures / 48 placeholders / 16 noise / 0 real |
| ripsecrets | 6 | 55 | 33 fixtures / 21 placeholders / 7 noise / 0 real |

- Human auditors classified **zero** findings from any tool as plausibly-live secrets; Claude's blanket suppression matches the human ground truth exactly.
- gitleaks/ripsecrets noise is mostly *defensible* (real-format dummy fixtures in Rails tests, e.g. a Mailgun webhook token fixture that gitleaks reports 11 times for one value — no dedup). detect-secrets' 247 and Klarion's pre-AI 93 are dominated by genuine noise: RDoc `+markup+` prose, MD5 self-test constants, i18n strings, even the integer literal `18446744073709551615` (2⁶⁴−1).
- The audit also caught a Klarion detector bug: a **duplicate finding emitted for the same line** (`activerecord/lib/active_record/store.rb:17`, generic-high-entropy twice).

## 4. Speed

Scan stage (hyperfine, ≥5 runs, warm cache):

| Tool | leaky-repo (704 KB) | rails (51 MB) |
|---|---|---|
| **Klarion (scan stage)** | **12.9 ms ± 1.9** | **0.61 s ± 0.02** |
| gitleaks | 35.4 ms ± 1.2 | 2.84 s ± 0.11 |
| ripsecrets | 50.9 ms ± 3.3 | 1.26 s ± 0.02 |
| trufflehog | 1.13 s ± 0.02 | 2.14 s ± 0.02 |
| detect-secrets | 1.44 s ± 0.10 | 11.96 s ± 0.21 |

**On scan scope.** Klarion's default config skips files over 1 MiB and a list of
binary/lockfile/vendor globs, so it is not reading byte-for-byte what every other
tool reads. On rails it content-scans 4,827 of the 4,967 files present (97%), and
on flask 227 of 236 (96%) — the skipped remainder is images, lockfiles and
minified assets. The gap is small enough that it does not explain a 2–4.6×
difference, but the comparison is "each tool at its defaults", not "identical
byte counts", and every other tool applies default exclusions of its own.

AI adjudication (single run, via `claude -p`, sequential batches of 10): leaky 736 s, flask 85 s, rails 2,196 s. This is CLI-transport overhead, not model cost — each batch spawns a full Claude Code CLI process. The Messages API path is dramatically cheaper per batch and now dispatches `ai.max_concurrency` batches in parallel (default 4), but **that configuration has not been benchmarked** — treat it as unmeasured until it appears in a table here. The verdict cache collapses duplicate candidates within a single scan; it is process-local by design, so it does not make *re-scans* cheaper (persisting it would mean writing model-authored verdict text, which routinely quotes the candidate, to disk).

## 5. Git-history scanning (leaky-repo, 25 real commits)

| Tool | Findings | Files |
|---|---|---|
| klarion `git --history` | 103 | 21 |
| gitleaks `git` | 26 | 13 |
| trufflehog `git` | 12 | 8 |

detect-secrets and ripsecrets do not scan history. Counts are candidate-stage (no GT exists for historical states); Klarion's higher count reflects its broader generic rules — the same AI adjudication applies in history mode.

## 6. Feature matrix

| | Klarion | gitleaks | trufflehog | detect-secrets | ripsecrets |
|---|---|---|---|---|---|
| Language | Go (static binary, 2 deps) | Go | Go | Python | Rust |
| Detection | 83 rules + Rényi entropy + **AI adjudication** | ~222 regex rules + entropy thresholds | ~1,000 provider detectors | 27 plugins (regex+entropy+keyword) | 28 patterns + 1 generic |
| Live-credential verification | no (roadmap) | no | **yes — core feature** | partial (some plugins) | no (never phones home) |
| FP handling | AI verdicts + baseline + allowlists | baseline + .gitleaksignore + allowlist | verification filter | **baseline/audit workflow** | .secretsignore |
| Git history | yes | yes | yes | no | no |
| Pre-commit / hooks | yes (`klarion hook`, `git`) + **Claude Code plugin + MCP server** | yes | yes | yes | yes (primary use) |
| Output formats | text/json/sarif/junit/gitlab | json/csv/junit/sarif/template | text/json | json baseline | text |
| License | MIT | MIT | **AGPL-3.0** | Apache-2.0 | MIT |
| Maintenance | pre-release | ~28k★, active | ~27k★, very active (weekly) | ~4.6k★, **no release since 2024** | ~0.9k★, slow |

Not benchmarked (docs-only): **ggshield** (500+ detectors but SaaS — sends code to GitGuardian's API, account required), **Semgrep Secrets** (semantic dataflow analysis, paid product), **git-secrets** (AWS-only patterns, effectively legacy). None fit the "local, no account" comparison scope.

## 7. Klarion detection gaps — ranked roadmap (from the miss analysis)

24 of 42 risk files missed at the candidate stage; verified causes, by cost:

1. **Heuristic verifier over-suppression** (8 files, recall 0.43→0.62 if fixed): the offline "example/test/dummy context" rule kills keyword-anchored matches it shouldn't. The AI verifier already recovers most of these; fix the heuristic for no-AI/hook mode.
2. **Structured credential files with no `key=value` shape** (6 files): `.netrc`, `.pgpass`, `.esmtprc`, `.git-credentials` (URL-userinfo), FileZilla XML. Fix: filename-gated rules (path-glob predicate on `rules.Rule`).
3. **Language-syntax blind spots** (4 files): `define('DB_PASSWORD', '…')` PHP calls, `SECRET_KEY = '…'` with punctuation-rich values. Fix: comma separator + quoted-value capture in generic rules.
4. **Placeholder/entropy gates too aggressive** (3 files): `UserPassword123` dies to substring stopword check; Firefox `logins.json` encrypted blobs rejected. Fix: anchored stopword matching for rule-based hits.
5. **Missing key names** (2 files): `pass`, `passphrase`, `*_PASS` not in the password alternation.
6. **Identifier-shape vetoes** (hub, .npmrc): 40-hex/UUID demoted to "commit SHA/id" even when the key says `oauth_token:`/`_authToken=`. Key context must outrank shape.

## 8. Bugs found and fixed during this study

1. **Verdict misassignment (critical, fixed):** `cacheVerifier` passed deduplicated batches to providers with sparse original indices; providers map echoed indices positionally → verdicts silently dropped or **assigned to the wrong candidate**. Fixed by positional re-indexing at three layers + regression tests (`internal/verify`).
2. **Model under-fill (fixed):** haiku occasionally returns fewer verdicts than candidates; unresolved candidates now get re-queried (refill loop) instead of silently defaulting to "uncertain".
3. **Duplicate finding on one line** (open): two identical generic-high-entropy findings for `store.rb:17` in rails.
4. **Transient CLI failures aborted `on_error=fail` scans** (fixed): claude-cli calls now retry with backoff.

## 9. Limitations

- leaky-repo secrets are realistic-format but synthetic (author-randomized); no gated datasets (SecretBench) or very large labeled corpora (Samsung CredData) were used.
- File-level scoring (the dataset's GT is per-file counts, not per-line labels).
- Clean-corpus "0 findings" treats committed dummy fixtures as correct suppressions (matches Klarion's design intent; a stricter policy would surface fixtures too).
- Single-run wall times for AI adjudication; `claude -p` transport is not representative of API deployment.
- trufflehog benchmarked with verification off (its core differentiator needs live credentials, untestable on synthetic corpora).
- detect-secrets audit composition extrapolated from a 73/247 stratified sample.

## 10. Addendum — structural suppressors for the no-AI path

*Added after the original run. The rows above marked "after the fix" come from
here; every other number in this report is from the original run and unchanged.*

### Why this mattered

`ai.mode` defaults to `auto` — "use AI when credentials are available". Most CI
has no `ANTHROPIC_API_KEY`, so **the default install is the "Klarion candidates"
row, not the Klarion-AI row**: 99 findings on clean corpora, noisier than
gitleaks' 33. The headline precision claim described a configuration most users
would never run. That is a conditional advantage, not a structural one.

### What was fixed

Two changes, both in the offline verifier path:

1. **`capContext` dropped the matched line.** The detector emits `contextRadius`
   (3) lines either side of a candidate, so the snippet is 7 lines with the match
   in the middle. `capContext` took a *head* slice — at the default
   `max_context_lines = 3` the verifier received the three lines *preceding* the
   match and never the line containing the secret. Now centered on the match.
   This alone is why recall rose: the heuristic was judging blind.
   The AI benchmark used `max_context_lines = 5`, where the head slice still
   included the match, so **no AI-path number in this report is affected**.

2. **Structural suppressors** (`internal/verify/suppress.go`) — addressing gap 1
   (heuristic over-suppression) and gap 4 (aggressive stopword gates) by keying
   off *code structure* instead of value entropy:
   comment/doc lines · RDoc `+markup+` · code expressions and identifiers on the
   right-hand side of an assignment · Ruby symbols · runtime `#{}`/`${}`
   interpolations · CLI flags · known digest constants (md5("hello") et al) ·
   long decimal integers · placeholder credentials incl. inside connection URIs ·
   entropy-only matches in prose documentation.

### Recall protection

Every suppressor except the placeholder/URI rules is gated to **generic
(entropy-only) matches**; a provider-pattern hit (`AKIA…`, `sk_live_…`, `ghp_…`)
is never suppressed by shape, even in a comment or a doc file.

Two iterations were rejected for costing recall, both caught by diffing
detections against the pre-change binary:

- Suppressing *any* unquoted value destroyed recall (98 → 20 findings): PEM key
  bodies, `.env` values, `/etc/shadow` and `.htpasswd` entries are all unquoted
  real secrets. The rule now requires positive evidence of code — call/index
  punctuation, a dotted call chain, or a snake_case identifier.
- The `+markup+` and `//`-comment patterns both matched base64 key material
  (`+SY+Yv0J…`, lines beginning `//`), silently dropping 15 private-key
  detections. Both now require far stricter anchoring.

`internal/verify/suppress_test.go` locks this in: one table asserting each
false-positive class is suppressed, and a second asserting real credentials from
leaky-repo are **not** — the latter is the regression guard that matters.

### Result (neutral config, no API key)

> **These numbers do not generalize.** Each suppressor below was written in
> response to a false positive in flask or rails, then scored on flask and rails.
> [§12](#12-addendum--the-no-ai-path-does-not-generalize) re-runs the same
> configuration on four unseen repositories and gets 1,516 findings.

| no-AI configuration | clean-corpus FPs | risk-file recall | file precision | F1 |
|---|---|---|---|---|
| before | 99 | 0.43 | 0.90 | 0.58 |
| after structural suppressors | 0 | 0.55 | 0.92 | 0.69 |
| **after path-anchored non-prod matching** | **0** | **0.62** | **0.93** | **0.74** |

Recall now exceeds detect-secrets (0.62 vs 0.55), the previous recall leader,
with 0 false positives against its 247, and F1 0.74 against its 0.70. Zero
detections were lost at either step relative to the preceding binary.

### Third iteration — path-anchored non-production matching

The "test/example/docs context" rule matched its markers as **substrings** of the
file path and of the surrounding lines. That is unsound in both directions:

- `api/latest/config.go` was read as a test path, because `latest` contains
  `test`. So was any candidate within three lines of the word `specify`
  (contains `spec`) or a `https://…/example.com` URL.
- A generic match suppressed this way is returned as `false_positive` at
  confidence 0.75 — above the 0.6 `min_confidence` — so it was dropped from the
  report entirely rather than demoted.

Matching is now anchored: directory names are compared as whole slash-separated
path segments, file names as whole `._-` separated tokens, and only markers that
describe the *value itself* (`fixture`, `dummy`, `placeholder`, `for testing`, …)
are matched against surrounding code, on word boundaries.

Recovered on leaky-repo: `.docker/.dockercfg`, `.docker/config.json` and
`cloud/heroku.json` — three real credential files named in §7 gap 1 as heuristic
over-suppressions. Clean corpora stayed at 0 findings; the one new Rails
candidate this exposed (`…/generators/active_record/model/USAGE`, a generator
usage doc whose `password:digest` example had been suppressed only by the
accidental `specify`/`spec` match) is now handled by recognizing conventional
extensionless prose files (`USAGE`, `README`, `CHANGELOG`, …) as documentation.

Reproduce (must pass `--config`, or the repo's own `.klarion.toml` is
auto-discovered and skews the result):

```bash
klarion scan benchmark/datasets/fp-rails benchmark/datasets/fp-flask \
  --config benchmark/harness/klarion-neutral.toml --ai-mode off --format json
klarion scan benchmark/datasets/leaky-repo \
  --config benchmark/harness/klarion-neutral.toml --ai-mode off --format json
```

Gaps 2, 3, 5 and 6 in §7 are untouched and remain the roadmap.

## 11. Reproduce

```bash
cd benchmark
python3 harness/run_benchmark.py                    # all tools, all datasets
python3 harness/run_benchmark.py klarion-ai leaky    # one tool, one dataset
python3 harness/make_report_tables.py               # regenerate tables
```

Scores: `results/accuracy.json` · agent study (audits, gaps, features, verification): `results/study.json` · timing: `results/timing-*.json`. Raw tool output is regenerated locally into `results/raw/` and is deliberately not committed — see the note at the top.

---

## 12. Addendum — the no-AI path does not generalize

*Added 2026-08-08, after §10. This section exists because §10's headline number
is overfit and was being quoted as a general claim.*

### Why this was measured

The structural suppressors in §10 were written **in response to** the 99 false
positives that flask and rails produced. Measuring 0 false positives on flask and
rails afterwards demonstrates that the fix worked on flask and rails. It is not
evidence that it generalizes, because the corpora that motivated each rule are
the same corpora used to score it.

Flask and rails are also Python and Ruby: two languages that share a short
`snake_case` identifier convention. Nothing in the original benchmark exercised a
language with long `CamelCase` or `SCREAMING_SNAKE` identifiers, and nothing
exercised a repository that vendors compiled JavaScript or ships a corpus of test
certificates.

### Method

Four repositories, four ecosystems, none used to develop any Klarion heuristic.
Shallow clone at HEAD, scanned with `--ai-mode off` and a neutral config (no
`.klarion.toml` in scope, so stock defaults only).

```sh
klarion scan <repo> --ai-mode off --show-suppressed --format json
```

### Result (no AI, unseen corpora)

| repo | ecosystem | files scanned | findings | suppressed |
|---|---|---:|---:|---:|
| spring-boot | Java | 11,409 | **930** | 4,469 |
| terraform | Go / HCL | 5,380 | **367** | 1,482 |
| next.js | TypeScript / JS | 28,757 | **174** | 1,306 |
| symfony | PHP | 14,208 | **45** | 1,029 |
| **total** | | **59,754** | **1,516** | 8,286 |

Against §10's 0 findings on 3,700 files, the no-AI path produces 1,516 findings
on 59,754 files of comparably clean code. Sampling the source lines, essentially
all are false.

### False-positive classes, and why flask and rails could not surface them

| class | example | count |
|---|---|---:|
| Armored blocks reported once per base64 line | two embedded `-----BEGIN PGP PUBLIC KEY BLOCK-----` in `getproviders/public_keys.go` (175) and `releaseauth/signature.go` (121); `.crt` / `.pem` / `.key` test fixtures | 296 of 367 in terraform, 857 of 930 in spring-boot |
| Long identifiers read as high entropy | `SseCustomerKeySHA256AttrName:` (Go struct field), `function applyDecs2301Factory() {` (JS), `PROVIDER_SECURITY_TOKEN = "TENCENTCLOUD_SECURITY_TOKEN"` (env var *name*) | most of terraform's remaining 71, and next.js outside `compiled/` |
| Vendored and compiled bundles | `packages/next/src/compiled/@babel/runtime/…` | 150 of 174 in next.js |
| Public hashes and test URLs | `sha384-…` SRI hash (public by design); `redis://` in `PredisAdapterTest.php` | most of symfony's 45 |

**Correction, 2026-09-15.** An earlier revision of this table attributed 365 of
terraform's 367 findings to the identifier class. That was wrong. Re-reading the
source lines, 296 of the 367 are in two files that embed PGP public key blocks as
string literals, flagged once per line of base64 body. The identifier class is
real — it is the dominant class in next.js and in terraform's remainder — but
terraform's headline number was mostly a per-line reporting bug, not an entropy
failure. That bug is fixed; see the collapse pass note below.

Two distinct problems hide in this table, and only one is about entropy.

The **identifier class is the substantive one.** Normalized entropy cannot
distinguish a long CamelCase identifier from a credential, because on that metric
they are not distinguishable. Only a verifier that reads the surrounding code can,
which is precisely the thing the no-AI path removes.

The **armored-block class was a defect.** One credential spanning thirty lines was
emitted as nineteen findings. §3 of this report criticises gitleaks for reporting
one fixture eleven times without dedup; Klarion was doing the same thing, worse.
It inflated every number in this section and cost one model call per line.

### The AI configuration on the same corpora

The first attempt at this table failed on the benchmark machine: a local
`claude-mem` `SessionEnd` hook cancels nested `claude -p` invocations, so 16 of 21
batches errored, and under `on_error = "fail_open"` the unverified candidates were
retained and inflated next.js to 385 findings. That figure was a transport
artifact and is not cited here.

Re-measured 2026-08-08 in a clean Linux environment with no such hook,
`on_error = "fail"` so that no run can contain an unadjudicated candidate, and the
corpora run **sequentially** — four in parallel put roughly sixteen concurrent
adjudications against one account and every corpus aborted at batch ~35 on rate
limiting. The entropy-only baseline was reproduced exactly first (930 / 367 / 174
/ 45 findings, 4,469 / 1,482 / 1,306 / 1,029 suppressed), so the two columns below
are directly comparable.

| repo | candidates (no AI) | findings (AI on) | removed |
|---|---:|---:|---:|
| spring-boot | 930 | **272** | 71% |
| terraform | 367 | **26** | 93% |
| next.js | 174 | **10** | 94% |
| symfony | 45 | **8** | 82% |
| **total** | **1,516** | **316** | **79%** |

Adjudication removes 79% of what the pre-filter emits on code it has never seen.
It resolves the identifier class outright: terraform's Go struct fields and env
var names, next.js's compiled Babel output. What survives is 316 findings across
**34 files**, and almost all of it is the armored-block defect — spring-boot's 272
are 18 private keys at roughly 19 findings each, every one under `src/test`,
`dockerTest`, `smoke-test` or `testFixtures`.

Two caveats on these numbers.

**Transport affects the verdict.** symfony scores 45 → 0 when `claude -p` runs with
its default tool access and 45 → 8 with tools disabled. The agentic loop reads the
surrounding files and correctly identifies test fixtures, at four to fifteen times
the latency and many turns per candidate. The table above is the tool-free
configuration, which is what ships. The earlier 45 → 0 was the agentic one.

**These predate the collapse pass.** Armored blocks are now merged into a single
finding before adjudication, which on the same corpora takes the entropy-only
output from 1,516 to **263** with no model calls at all — spring-boot 930 → 114,
terraform 367 → 80, next.js 174 → 24, symfony unchanged at 45. The AI column has
not been re-measured since that landed. It will improve, by roughly the factor the
per-line inflation accounts for, but **no re-measured figure exists yet and none
should be quoted.**

### Conclusion

The no-AI path is a degraded mode, not a product configuration, and §10's 0 should
never have been presented as a general result. Documentation, marketing copy, and
the GitHub Action now state that a model is required. The pre-filter's purpose is
to keep AI token cost low by shrinking the candidate set — it was never an
independent detector, and it does not behave like one.

Adjudication does the job it is there for: 79% of the pre-filter's output removed
on four unseen ecosystems, and the identifier class — the one entropy cannot
solve in principle — resolved. It does not reach zero. The gap is test-fixture key
material, and the measurement that found it also found the per-line reporting
defect that was inflating it.
