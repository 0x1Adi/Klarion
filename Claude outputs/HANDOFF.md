# Klarion — session handoff, 2026-09-16

## What Klarion is

A secret scanner in Go. Two stages: deterministic detection (83 rules + Rényi
entropy) generates candidates, then an LLM adjudicates each one. **The model is
the product; the entropy pass is a cost-reduction prefilter, not a detector.**
Requires an API key — `ai.mode` defaults to `"on"` and a missing key is a hard
error (exit 2), not a fallback.

- Repo: `github.com/0x1Adi/Klarion` (SSH remote), local at `~/ai-project/secret-detector-ai`
- Listed on GitHub Marketplace as of v0.2.2 — Security (primary), Code Scanning Ready (secondary)
- Current tags: `v0.2.2`, moving `v0`. `v0.1.0`, `v0.2.0`, `v0.2.1` are marked pre-release (all broken)

## Where it stands vs the market

**One line: technically interesting, commercially unproven.** The only
head-to-head data is on the two corpora it was tuned against, and it loses on F1
there.

| | Klarion | gitleaks | trufflehog | detect-secrets |
|---|---|---|---|---|
| Adoption | ~0 | ~28k★ | ~27k★ | ~4.6k★ |
| Needs API key | **yes** | no | no | no |
| Recall (leaky-repo) | 0.43 | 0.31 | 0.19 | **0.55** |
| F1 | 0.60 | 0.47 | 0.32 | **0.70** |
| FPs on flask+rails | **0** | 33 | 9 | 247 |

Strongest defensible claim: zero false positives on 3,700 files where others
produce 9–247, plus a genuine research finding (entropy detection has a language
bias — Go/Java/JS CamelCase and SCREAMING_SNAKE read as high entropy; Python and
Ruby snake_case does not, so every scanner tuned on Python/Ruby corpora is
tuned on the easiest case).

## Measured results

**§13 of `benchmark/REPORT.md`** (written this session, may be uncommitted —
check first):

Seeded 15% file-level sample, `SEED=1729`, four unseen corpora (spring-boot,
terraform, next.js, symfony), Groq `openai/gpt-oss-20b`, `reasoning_effort=medium`,
`max_batch=10`, `max_context_lines=2`.

| corpus | candidates | findings | removed | 95% CI |
|---|---:|---:|---:|---|
| spring-boot | 25 | 7 | 72% | 54–90% |
| terraform | 21 | 2 | 90% | 78–100% |
| next.js | 6 | 0 | 100% | — |
| symfony | 10 | 6 | 40% | 10–70% |
| **pooled** | **62** | **15** | **76%** | **65–86%** |

**Only the pooled number is quotable.** Per-corpus n is too small.

Note: `uncertain` verdicts are kept and count as findings, so this is a floor,
not the model's accuracy.

## Open work, highest value first

1. **Commit `benchmark/REPORT.md`** if still dirty — §13 was written but not committed.
2. **Head-to-head against gitleaks / trufflehog / detect-secrets** on the same four
   corpora, same 15% sample, same seed. No API keys, no quotas, one afternoon.
   This is the missing experiment: §13 measures Klarion against its own prefilter,
   which says nothing about beating anyone. Without it the launch claim is
   self-referential.
3. **README still cites `1,516 → 316`** from §12. Not comparable to §13 (different
   clone dates, pre-collapse, full rather than sampled). Needs a short edit
   pointing at §13 for the current configuration.
4. **Recall is 0.43 and no prompt fixes it.** The model only sees candidates the
   detector produced. §7 of REPORT.md ranks all 24 misses; gap #2 alone
   (filename-gated rules for `.netrc`, `.pgpass`, `.git-credentials`, FileZilla
   XML) is worth ~6 files. **To move recall you write rules, not prompts.**
5. `SAMPLE=0.5` re-run would take pooled n to ~250 (±6 points) and make the
   per-corpus column usable. Cache makes it cheap.
6. **Launch** — full copy already written at project doc `claude/klarion-launch.md`
   (Show HN, r/netsec, X thread, outreach emails, sequencing).
7. Minor: `occurrences` isn't surfaced by any reporter, so a collapsed 19-line key
   prints as one finding with no indication of its span. `action.yml` uses
   `actions/checkout@v4` (Node 20) and `codeql-action@v3` (deprecated Dec 2026).

## Eight defects found this session

All fixed, all tested, all only reachable with a real provider under load — none
visible to the Go test suite, none reproducible against a stub. **This is the
Show HN story, stronger than the percentage.**

1. `parseBatchResults` sliced first `{` to last `}` — two objects became `{...},{...}`, scan aborted
2. Verdicts emitted without the `results` wrapper were discarded
3. `Retry-After` parsed with `strconv.Atoi` — Groq sends `20.3775`, discarded, retried too early
4. Request timeout wrapped the whole retry sequence, so a 20s wait inside a 45s budget killed the batch
5. An unanswerable batch was lost rather than split
6. No progress output during adjudication — a 30-minute scan looked like a hang
7. `reasoning_effort` never sent — a reasoning model billed its scratchpad, ~3× token use
8. `*.base64` not ignored — an encoded PNG scanned as five candidate secrets

Also fixed earlier: shell injection in `action.yml`, a manifest that referenced
the `secrets` context (composite actions have none — made the Action unloadable
for every consumer of v0.2.0/v0.2.1), armored-block collapse (one PEM key was
reported once per base64 line, 19× on spring-boot), and `ai.mode` defaulting to
`auto` while the docs said a model was required.

## Environment gotchas

**Two GitHub identities.** `git` pushes over SSH as `0x1Adi`; `gh` authenticates
as `adityatiwari-avataar` and lacks rights on `0x1Adi` repos. Symptom: `gh`
commands 404 or 403, HTTPS remotes get "Permission denied". **Always use SSH
remotes**; run `gh auth switch --user 0x1Adi` before any `gh` operation.

**Claude cannot push.** The cloud sandbox has no credential for this repo (git
proxy refuses), no `gh` binary, and no GitHub API. The device bridge VM has no
network to GitHub at all. Claude writes files to disk; **the user runs every
git command.**

**Don't run git through the device bridge.** It can write files but not unlink
them, so every git command leaves a stale `.git/*.lock` behind, which breaks the
next command. This wedged `git gc` once.

**`.github/` is protected from remote writes.** Workaround: write to the repo
root as `_staged_<name>` and have the user `mv` it into place.

**The stop hook false-positives.** `~/.claude/stop-hook-git-check.sh` reports
uncommitted changes when the tree is clean — usually a stale `.git/index.lock`.
Verify with `git --no-optional-locks status --short` before believing it.

**Go version.** `go.mod` requires 1.25; the sandbox has 1.24. Claude builds with
a local-only `sed 's/^go 1.25$/go 1.24/'` on a *copy* — never commit that.

**Groq is unreachable from the sandbox** (egress policy), so Claude cannot run
the benchmark. The user runs it.

## Benchmark harness

`~/Downloads/rerun.sh` (source also in the session, not in the repo). Env vars:

```bash
GROQ_API_KEY=gsk_... SAMPLE=0.15 BATCH=10 CONTEXT_LINES=2 ~/Downloads/rerun.sh
# PROVIDER=ollama MODEL=gemma4:latest   # local, no quota, weaker model
# PROVIDER=claude-cli MODEL=haiku       # 29s/call on this machine — too slow
```

Verdicts cache to `~/klarion-bench/verdicts.json` and flush every 25, so an
interrupted run resumes. Corpora clone to `~/klarion-bench/`.

**Groq free tier: 8K TPM / 200K TPD.** A full four-corpus run at 15% sample fits
in roughly one day. `reasoning_effort` matters enormously — default effort burned
a whole day's quota in ~25 batches.

## Working style that worked

The user is a founder shipping, not researching. Short answers, plain English,
no hedging. They explicitly asked for pushback and acted on it every time —
including retracting a published benchmark claim when the data contradicted it.

Two things to keep doing: **verify before asserting** (several of this session's
findings came from actually reading the code rather than reasoning about it), and
**say when you were wrong** — at least three of my own claims this session were
incorrect and correcting them promptly mattered more than being right first.
