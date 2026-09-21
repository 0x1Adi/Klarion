# Klarion — Design & Architecture

Status: living document. This is the source of truth the implementation follows; when code and this document disagree, one of them is a bug.

Module: `github.com/0x1Adi/Klarion` · Go 1.25 · dependencies: standard library + `spf13/cobra` + `BurntSushi/toml` only.

---

## 1. Goals & non-goals

### Goals

- **Catch secrets written by AI coding agents at the earliest possible moment** — ideally before the bytes hit disk (write-time), otherwise before they are committed (commit-time), and always in CI as a backstop.
- **Near-zero false positives, via adjudication.** A scanner that cries wolf gets disabled. Klarion spends a cheap deterministic pass to find candidates and an AI pass to adjudicate them with context, so what fails a scan is a *real* leak. **The AI pass is required, not optional.** The deterministic pass is a cost-reduction device — it shrinks the candidate set so the model reads hundreds of strings instead of millions — and it is not a detector on its own. Run without a verifier it emits raw entropy output, measured at 491 findings across four clean unseen repositories at v0.4.3 ([REPORT §16](./benchmark/REPORT.md#16-addendum--cross-tool-false-positive-load-and-the-language-effect-2026-09-21)); the 2026-08-08 build measured 1,516 ([§12](./benchmark/REPORT.md#12-addendum--the-no-ai-path-does-not-generalize)).
- **Portable, tunable entropy detection** via normalized Rényi entropy that behaves consistently across token lengths and alphabets.
- **One binary, every surface**: CLI, git pre-commit, CI, Claude Code hook, MCP server. No runtime dependencies.
- **Fail closed on security, fail open on ergonomics.** Uncertain verdicts count as secrets; internal scanner errors in a hook never block the user's work.
- **Never leak the secret it's protecting.** Raw secrets are never serialized or logged.

### Non-goals

- Not a general SAST/vuln scanner — secrets only.
- Not (yet) a live-credential validator (that's on the roadmap; trufflehog occupies that niche today).
- Not a git-server-side or org-wide scanning service — Klarion is a local/CI tool, though its outputs feed such systems (SARIF).
- Not a replacement for a secrets manager; it tells you to *use* one.

---

## 2. Threat model

The primary adversary is **accidental leakage**, amplified by AI agents:

- **AI agents hardcoding secrets.** An agent, asked to "wire up the Stripe client," pastes a real key it saw in context, or invents a plausible-looking one, directly into source. This happens *as the agent writes*, faster than any human review cadence.
- **Commit-time leakage.** A developer (or agent) `git commit`s a `.env` file, a config with a live token, or a debug print of a credential.
- **Write-time leakage.** The secret is being written to a file *right now* by a tool call, and we want to intercept the `Write`/`Edit` before it lands.

Interception points, in order of preference:

1. **Write-time** — Claude Code PreToolUse hook + MCP: stop it before it's on disk.
2. **Commit-time** — git pre-commit hook: stop it before it's in history.
3. **CI/audit** — standalone scan: stop it before it merges/releases, and find what already leaked.

Out of scope: a malicious agent actively trying to exfiltrate secrets past the scanner (Klarion raises the cost of accidents, it is not a sandbox), and secrets that never appear as literals (e.g. assembled at runtime from parts).

---

## 3. The two-stage pipeline

```
sources (files / git diff / stdin / MCP text)
        │
        ▼  internal/detect
┌─────────────────────────────────────────────┐
│ STAGE 1  —  fast deterministic detection     │
│   per line:                                  │
│     keyword prescreen → rule regex → guards  │  curated rules  (internal/rules)
│     tokenize → normalized Rényi score        │  entropy sweep  (internal/entropy)
│   emit candidate Findings (+ redacted ctx)   │
└─────────────────────────────────────────────┘
        │  []finding.Finding  (Verdict = unverified)
        ▼  internal/verify
┌─────────────────────────────────────────────┐
│ STAGE 2  —  AI adjudication                  │
│   batch candidates → Verifier.Verify()       │  anthropic / openai / ollama / heuristic
│   assign Verdict{status,confidence,reason}   │
│   filter confident false_positives           │
└─────────────────────────────────────────────┘
        │
        ▼  internal/report
   text / json / sarif / junit / gitlab   +   exit code
```

### 3.1 Rényi entropy rationale

The generic detector must decide "does this token look like random key material?" without knowing the format. Three design decisions:

- **Order α = 2 (collision entropy).** For α > 1, Rényi entropy `H_α = 1/(1-α)·log2(Σ pᵢ^α)` weights the *most probable* symbols most heavily, so it punishes the skewed byte distributions of human-written text (English, camelCase identifiers, dotted paths) more sharply than Shannon (α = 1) does. Collision entropy (α = 2) has a clean closed-form expectation for the uniform case, which we exploit for normalization. α stays configurable (`entropy.alpha`); α → 1 recovers Shannon exactly.

- **Normalization against expected random entropy.** Absolute entropy grows with both length and alphabet size, so no fixed bit threshold is portable. We divide the token's `H₂` by the **expected collision entropy of a uniformly random string of the same length `n` over the same `k`-symbol alphabet**. The normalizer is the exact expectation of the empirical collision probability:

  ```
  E[ Σᵢ p̂ᵢ² ] = 1/n + (n-1)/(n·k)        →   ExpectedCollision(n,k) = -log2(that)
  ```

  By Jensen this is a slightly conservative (low) estimate of `E[H₂]`, which is fine — it makes the normalizer stable for short samples without over-rewarding them. The resulting `NormalizedScore` clusters near **1.0** for real keys and falls off for structured/natural text, and is **clamped to [0, 1.25]** to bound sampling noise on short tokens.

- **Character-class inference.** `Classify` picks the *smallest* class containing every byte (digits ⊂ hex ⊂ lower/upper ⊂ alphanum ⊂ base64 ⊂ printable), with a guard that mixed-case hex-looking strings fall through to alphanumeric. Using the tightest class means a 40-char hex hash is normalized against a 16-symbol alphabet (so it does *not* falsely score as maximally random), while a genuine base64 key is normalized against 64 symbols.

### 3.2 Threshold policy

Two thresholds, chosen by whether the token sits near a secret-ish keyword on the same line:

| Context | Config key | Default | Severity |
| --- | --- | --- | --- |
| near `password`/`token`/`key`/… | `entropy.threshold` | 0.88 | high |
| no such keyword | `entropy.threshold_no_context` | 0.95 | medium |

Pre-filters that run before scoring (cheap kills for the common false positives): `min_length` (clamped ≥ 16) / `max_length` bounds, `require_digit` (real keys almost always contain digits; kills identifier/camelCase noise), UUIDs, git SHAs (40-hex in commit context), content digests (64/128-hex in digest/checksum context), placeholder detection (stopword substrings, long repeat/sequential runs, too few distinct characters for the length), and the global secret allowlist.

### 3.3 Tokenization

`tokenize` extracts runs of `[A-Za-z0-9+_-]{16,}` and re-absorbs trailing base64 `=` padding. The class deliberately **excludes `/`, `.`, and `=`** so that URLs, domains, dotted paths, and `KEY=value` assignments don't glue into giant pseudo-tokens. Rule-covered spans are skipped so a token isn't reported twice.

---

## 4. Package layout

| Package | Responsibility |
| --- | --- |
| `internal/finding` | Core shared types: `Finding`, `Severity`, `Verdict`/`VerdictStatus`, redaction (`Redact`, `RedactInText`), stable `ComputeFingerprint`. No dependencies on other Klarion packages. |
| `internal/entropy` | Rényi entropy (`Renyi`, `Shannon`), charset classification (`Classify`), and the normalized score (`NormalizedScore`, `ExpectedCollision`). Pure, no deps. |
| `internal/rules` | The `Rule` model and the built-in curated ruleset (`Builtin()` — see §12). |
| `internal/config` | Loads/validates `.klarion.toml` layered on `Default()`; compiled path/secret allowlists; glob matcher; `PathIgnored`/`PathAllowlisted`/`SecretAllowlisted`/`FingerprintAllowlisted`/`Stopwords`. |
| `internal/detect` | Stage 1: builds a `Detector` from config (built-in minus disabled + compiled custom rules), scans content/lines, applies guards, emits candidate findings with fingerprint + redaction + context. Concurrency-safe after construction. |
| `internal/verify` | Stage 2: `Verifier` interface + `Request`; providers (anthropic/openai/ollama), offline heuristic, verdict cache, and the `Apply` orchestrator that batches, filters, and applies the `on_error` policy. |
| `internal/scan` | Filesystem walk: honors `ignore_paths`, size limits, symlink policy, worker pool; drives `detect` then `verify`; aggregates results. |
| `internal/baseline` | Read/write the accepted-findings snapshot; suppress findings whose fingerprint is baselined. |
| `internal/git` | Shells out to the `git` binary; parses unified diffs into added-line sets (`FileDiff`) for staged/commit scanning; full-history audit. Shelling out (not a git lib) keeps behavior identical to the user's real git. |
| `internal/report` | Renders findings as text/json/sarif/junit/gitlab; applies redaction; honors `show_suppressed`. |
| `cmd/klarion` | Cobra CLI: root wiring, config discovery, exit-code mapping (§8), and each subcommand. |
| `internal/mcp` | The `klarion mcp` server: `scan_text`, `scan_file`, `verify_finding` tools over the MCP protocol. |

---

## 5. Verification design

The `Verifier` interface is intentionally tiny:

```go
type Verifier interface {
    Name() string
    Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error)
}
```

Contract: exactly one `Verdict` per `Request`, **in request order**; a returned error means the *whole batch* failed and the `on_error` policy takes over.

- **Batching.** Up to `ai.max_batch` (default 8) candidates per model call, to amortize latency/cost. `Apply` chunks the candidate set and dispatches up to `ai.max_concurrency` chunks (default 4) in parallel, so adjudication latency does not scale linearly with repository size. Implementations of `Verifier` must therefore be safe for concurrent use.
- **Structured outputs.** Providers request a strict JSON schema (array of `{index, status, confidence, reason}`) so parsing is deterministic; `index` re-associates verdicts even if the model reorders.
- **`on_error` fail-safe.** `keep` (default) leaves candidates `unverified` and *keeps them in the failing set* — a security tool must not silently drop findings when the AI is unreachable. `fail` aborts the scan (exit 2).
- **False-positive filtering.** When `filter_false_positives = true`, a `false_positive` verdict with `confidence ≥ min_confidence` (default 0.6) is removed from the failing set and moved to a suppressed list (reported only when `report.show_suppressed`). `uncertain` is **always treated as a secret**.
- **Caching.** A verdict cache keyed by a one-way hash of `(rule id, secret)` collapses duplicate candidates within a scan, and — when `ai.cache_path` is set — persists them between runs so CI never re-adjudicates unchanged code. The ledger is scoped to `provider:model`, so switching models does not inherit the previous judge's verdicts, and stores **only status and confidence**: never the secret, and never the model's `reason`, which quotes the candidate it describes. An `uncertain` verdict is not persisted, since it is the fallback a provider returns when it could not answer. Every failure mode (missing, corrupt, truncated, wrong scope, unwritable) degrades to "adjudicate again" — a cache is an optimization and must never fail a scan.
- **Offline heuristic.** A no-network `Verifier` (scores structure/placeholder signals) used when `mode = "off"`, or `mode = "auto"` with no credentials. `mode = "on"` — the default — requires a real provider and errors if none can be constructed, because a missing key is a misconfiguration rather than a reason to fall back.
- **Credential resolution.** The env var holding a provider's key is derived *from the provider* (`anthropic` → `ANTHROPIC_API_KEY`, `openai` → `OPENAI_API_KEY`; ollama and claude-cli authenticate out of band), with `ai.api_key_env` as an explicit override. There is deliberately no global default: one would mean a config naming one provider authenticates against another vendor's endpoint with the operator's key.
- **Retries.** Provider HTTP calls retry rate limits (429), request timeouts and 5xx up to 3 attempts with exponential backoff, honoring `Retry-After`. Non-transient statuses (401, 400) are surfaced immediately. Without this, one rate-limit blip silently costs a batch its verdicts while the scan still reports success.
- **Privacy in the request.** `Request.Secret`/`Context` carry the raw candidate only when `ai.send_secret = true`; otherwise they are pre-redacted before leaving the process. `max_context_lines` caps context volume.

---

## 6. Surfaces

### 6.1 CLI subcommands

Scan surfaces, and what each one is for:

| Invocation | Scans | Used by |
|---|---|---|
| `klarion scan [path]` | the working tree | local runs, CI on the default branch, audits |
| `klarion git` | the staged index | the pre-commit hook |
| `klarion git --base <rev>` | commits this branch adds, from the merge base | CI on a pull request |
| `klarion git --history` | every ref (branches, tags, stash), including what merge commits introduce | one-off audits of past leaks |

`--base` resolves through `git merge-base` rather than taking the base branch
tip literally: if the base branch has moved on since the branch was cut, a
two-dot range would otherwise attribute those commits — and their secrets — to
this change. A base revision missing from the local clone (a shallow CI
checkout) is a hard error naming the fix rather than a silently different scan.

| Command | Purpose |
| --- | --- |
| `klarion scan [path…]` | Scan a filesystem tree (default `.`). |
| `klarion git [--all]` | Scan staged changes (pre-commit); `--all` audits full history. |
| `klarion protect` | Install Klarion as a git pre-commit hook. |
| `klarion hook --event pre-tool-use [--bash]` | Claude Code PreToolUse adapter (reads hook JSON on stdin, writes a decision). |
| `klarion mcp` | Run the MCP server on stdio. |
| `klarion rules list` | Show the active ruleset. |
| `klarion baseline create` | Snapshot current findings as an accepted baseline. |
| `klarion version` | Print version/commit/date (injected at build time). |

Global flags: `--config`, `--no-color`, `--quiet/-q`, `--verbose/-v`.

### 6.2 Claude Code PreToolUse hook protocol

The hook reads the PreToolUse JSON on stdin (tool name + input: the file path and the content being written, or the Bash command line), extracts the would-be-written text, runs Stage 1 (+ Stage 2 when time/creds allow), and emits a JSON decision:

- On a real secret: `{"decision": "deny" | "ask", "reason": "<redacted explanation fed back to the agent>"}` — governed by `[hook] decision` and `[hook] block_on` (minimum severity to trigger).
- Clean, or `fail_open = true` and an internal error: allow (empty/permit decision), so scanner failures never block the user.

The `--bash` variant scans secret-bearing shell commands (e.g. an inline `export TOKEN=…` or a `git commit` that would introduce staged secrets). The plugin wires `Write|Edit|MultiEdit` and `Bash` matchers (see `claude-plugin/hooks/hooks.json`).

### 6.3 MCP tools

Exposed by `klarion mcp` (see `claude-plugin/mcp/servers.json`):

- `scan_text(text, [filename])` → findings for an in-memory blob (agent checks content before writing).
- `scan_file(path)` → findings for a file on disk.
- `verify_finding(...)` → run Stage 2 adjudication on a specific candidate.

All responses are redacted; raw secrets never cross the MCP boundary.

### 6.4 Git pre-commit

`klarion protect` writes `.git/hooks/pre-commit` invoking `klarion git`. `internal/git` shells to `git diff --cached`, parses hunks into added-line sets, and scans only added lines (a secret introduced by a commit lives on a `+` line, and the reviewer needs its new-file line number).

### 6.5 GitHub Action / GitLab CI

The standalone CLI with `--report sarif` (GitHub code scanning) or `--report gitlab` (GitLab secret_detection report). See README for ready-to-paste workflows. Ships in `.github/workflows/` (CI + release).

---

## 7. Performance & concurrency

- **Targets.** Stage 1 is the hot path and must sustain hundreds of MB/s of source: keyword prescreen before every regex, a single tokenizer pass, byte-array counting for entropy (no allocations per token), and hard caps (`maxLineScanLen`, `maxMatchesPerLine`, `maxFindingsPerFile`) to bound pathological inputs. Binary files are skipped via a NUL-byte sniff of the first 8 KiB.
- **Concurrency.** `internal/scan` runs a worker pool (`scan.workers`, default `NumCPU()`); a `Detector` is immutable after `New` and safe for concurrent use. Stage 2 concurrency is bounded by batch fan-out, not file count, to respect provider rate limits.
- **Cost control.** Stage 2 only ever sees Stage-1 candidates (a tiny fraction of tokens), batched, cached, and run against a cheap model (`claude-haiku-4-5`) — so AI cost scales with *suspected leaks*, not repo size.

---

## 8. Exit codes

`0` clean · `1` findings · `2` operational error. `cmd/klarion` maps a sentinel `errFindings` to `1`; any other error to `2`.

---

## 9. Security & privacy

- **Never serialize the raw secret.** `Finding.Secret`/`LineText`/`Context` are `json:"-"`; only a fixed-width redacted mask (`Redact`, which also hides the true length) is emitted. Context leaving the process is scrubbed with `RedactInText`.
- **Fingerprints hash, never store.** `ComputeFingerprint = sha256(ruleID ‖ path ‖ sha256(secret))[:32]` — stable across line drift and history rewrites, and reversible to nothing.
- **Allowlists & baseline.** Path globs, secret regexes, exact fingerprints, and extra stopwords (`[allowlist]`); a baseline snapshot suppresses known-accepted findings. Inline `klarion:allow` / `gitleaks:allow` markers skip a line.
- **Fail-safe defaults.** `on_error = keep`, `uncertain ⇒ secret`, `hook.fail_open = true` (ergonomics) vs. verdict fail-closed (security) are deliberately different axes.
- **Offline capable.** Heuristic verifier + local Ollama mean secrets need never leave the machine.

---

## 10. Configuration model

`config.Default()` supplies production defaults; `Load` layers TOML on top, rejects unknown keys, normalizes (clamps `min_length ≥ 16`, defaults `max_length`, `alpha`, batch/timeout; sets Ollama base URL), and compiles globs/regexes once. Discovery: `--config` → `$KLARION_CONFIG` → `.klarion.toml`/`klarion.toml` walking up to root → built-in defaults. See README §Configuration for the annotated key reference.

---

## 11. Testing strategy

Table-driven, hermetic (no network). Entropy: known scores for random vs. natural-language vs. structured tokens, charset classification edges, normalization stability across lengths. Detect: rule true/false positives, entropy threshold behavior with/without keyword context, placeholder/UUID/digest suppression, allowlist and fingerprint handling. Verify: a stub `Verifier` exercises batching, ordering, `on_error`, and false-positive filtering. Git: fixture diffs → added-line sets. The heuristic verifier and glob matcher get their own tables.

---

## 12. Curated ruleset catalog

Stage 1's rules are a **keyword-gated, entropy-guarded** set targeting the highest-value, highest-precision credential formats. Each rule is `{id, description, regex, secret_group, keywords, entropy?, min/max_len?, severity, tags, allowlist?}`. The keyword prescreen keeps the regex set cheap; the optional entropy floor and per-rule allowlists suppress structureless or well-known-fake matches. The starter set in `internal/rules/builtin.go` (`aws-access-key-id`, `github-pat`, `private-key`) is expanded to the catalog below (50+ rules, each with tests):

- **Cloud providers** (`cloud`): AWS access key id / secret access key / session token, GCP service-account key & API key, Azure client secret / storage key / SAS, DigitalOcean, Alibaba, IBM.
- **Version control & CI** (`vcs`, `ci`): GitHub PAT (`ghp_`), fine-grained PAT (`github_pat_`), OAuth/app/refresh tokens, GitLab PAT/CI job token, Bitbucket, CircleCI, Buildkite.
- **AI providers** (`ai`): Anthropic (`sk-ant-`), OpenAI (`sk-`/`sk-proj-`), Google AI, Cohere, HuggingFace (`hf_`), Replicate, Groq, Mistral — the formats agents are most likely to hardcode.
- **Payments** (`payments`): Stripe (`sk_live_`/`rk_live_`/`whsec_`), Square, PayPal/Braintree, Plaid, Shopify (`shpat_`/`shpss_`).
- **Messaging & comms** (`comms`): Slack (`xox[baprs]-`, webhook URLs), Twilio (`SK…` + auth token), SendGrid (`SG.`), Mailgun, Mailchimp, Postmark, Discord bot token/webhook, Telegram bot token.
- **Datastores & infra** (`infra`, `db`): connection URIs with inline credentials (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`), JWT (`eyJ…`), npm token, PyPI token, Docker/registry auth, Terraform Cloud, HashiCorp Vault, Datadog, New Relic, Sentry DSN, PagerDuty.
- **Keys & generic** (`key`): PEM private-key blocks (RSA/EC/OpenSSH/PGP), SSH keys, generic `password=`/`api_key=`/`secret=` assignments (entropy-gated), high-entropy base64/hex (`generic-high-entropy`, the Stage-1 entropy sweep).

Rule additions require: a precise regex with a `secret_group`, a keyword prescreen, a severity, tags, and table-driven positive/negative tests including at least one documented-fake value in the negative set.

---

## 13. Roadmap

- **Live-credential verification** (opt-in, network): confirm a candidate is *active* (à la trufflehog) to reach zero-FP on supported providers.
- **Incremental/daemon scan** for editor and long-running-agent integration.
- **Custom AI prompts & policies** per rule/tag; org-shareable config.
- **Richer baseline workflow** (expiry, review metadata).
- **Native git object walking** as an optional faster path for history audits.
- **More MCP tooling** (e.g. `explain_finding`, `suggest_remediation`).
