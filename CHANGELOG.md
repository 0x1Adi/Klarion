# Changelog

All notable changes to Klarion are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The verdict cache is written during a scan, not only at the end.** Flushing
  at `Close` meant a run killed by a rate limit, a daily token quota or Ctrl-C
  discarded every verdict it had already paid for — worst exactly when the cache
  is worth the most. The ledger now lands every 25 fresh verdicts, atomically,
  so an interrupted scan resumes instead of restarting.
- **Base64-encoded binaries are ignored by default** (`*.base64`, `*.b64`,
  `*.uu`). Such a file is maximum entropy by construction and never a
  credential, but the image-extension ignores miss it because the encoding
  extension comes last: symfony's `favicon.png.base64` produced five candidates
  on one line that the model could only answer "uncertain", and uncertain is
  kept — so an image landed in the report as five findings.
- **Verdicts emitted without the `{"results": ...}` wrapper are accepted.**
  Groq's `openai/gpt-oss-20b` returns one bare verdict object per candidate often
  enough to fail whole batches. A `status` field is what marks an object as a
  verdict, so unwrapped output is unambiguous and is now merged like any other.
- **A parse failure now prints what the model actually returned.** "no verdicts
  in model output" covered an empty completion, a refusal and a truncated
  response alike, none distinguishable from the error. A bounded snippet of the
  response is included; it can quote candidate text, so it goes only to the
  operator's terminal, never to a report or the cache.
- **A verdict that arrives in the reasoning channel is no longer lost.** At low
  reasoning effort some models leave `message.content` empty and put the answer
  in `message.reasoning`; reading only content failed the batch with "no verdicts
  in model output". Content is still preferred; reasoning is a fallback.
- **`ai.reasoning_effort` is forwarded to providers that support it.**
  Adjudication is classification, not deliberation, but a reasoning model left
  at its default spends most of its response budget narrating the decision — and
  those tokens are billed and rate-limited like any other. On Groq's
  `openai/gpt-oss-20b` the reasoning traces dominated token use by roughly 3x,
  exhausting a daily quota in about 25 batches. Empty by default, so
  non-reasoning models are unaffected.
- **Adjudication reports progress.** The slow stage produced no output at all,
  so a local model spending half an hour on one repository was indistinguishable
  from a hang. Batches done, percentage and an estimate from observed throughput
  now go to stderr, where they cannot contaminate a report on stdout.

### Fixed

- **Rate limits no longer abort a scan.** `Retry-After` was parsed with
  `strconv.Atoi`, so a fractional value — Groq sends `20.3775` — was discarded
  and the scan retried after 1s and 2s against a window with 20 seconds left to
  run. Every attempt was refused and the batch failed. Fractional seconds now
  parse, the delay is also read out of the error payload when the header is
  absent, retries go from 3 to 5, and the ceiling from 30s to 90s. A free-tier
  token-per-minute limit is a wait, not a failure.
- **A batch the model cannot answer is split instead of lost.** Under JSON mode
  a provider sometimes rejects its own output — Groq returns
  `400 json_validate_failed` with an empty `failed_generation`. That is a
  sampling failure, not a bad request, so it is now retried, and if the batch
  still cannot be answered it is halved and each half retried. Splits are
  contiguous, so verdicts stay in request order.
- **The request timeout now bounds one attempt, not the whole retry sequence.**
  `ai.timeout_seconds` wrapped every retry and every backoff wait together, so
  honouring a 20s Retry-After inside the 45s default left nothing for the retry
  and the batch died with `context deadline exceeded`. Each HTTP round trip gets
  the timeout; an overall ceiling derived from it still bounds the scan.

### Fixed

- **Model output with more than one JSON object no longer kills the scan.**
  `parseBatchResults` sliced from the first `{` to the last `}`, so two
  concatenated objects became `{...},{...}` and failed with `invalid character
  ',' after top-level value` — fatal under `on_error = "fail"`, and silently
  retained as unverified findings under `"keep"`. Observed from Groq's
  `openai/gpt-oss-20b` in JSON mode. Extraction is now brace-balanced and
  string-aware, verdicts are merged across objects rather than taking only the
  first (taking the first dropped verdicts, which then resolved as `uncertain`
  and were reported as findings), and a bare result array with no `results`
  wrapper is accepted. Unusable output is still an error, never a silent empty
  batch.

### Changed

- **`ai.mode` now defaults to `"on"` instead of `"auto"`.** A missing API key is
  a misconfiguration, and the scan now fails with exit 2 naming the variable it
  wants, rather than quietly falling back to the offline heuristic. Under
  `"auto"` a keyless run produced pre-filter output while the log still read as
  a successful scan — 1,516 findings across four unseen ecosystems where
  adjudication gives 316 — and the documentation already said a model was
  required. The default and the docs now agree. `--ai-mode auto` and
  `--ai-mode off` remain available as explicit opt-ins, and the GitHub Action's
  `ai-mode` input defaults to `on` to match.

## [0.1.0] - 2026-08-08

### Added

- **Diff scanning for pull requests.** `klarion git --base <rev>` (with optional
  `--head`, or an explicit `--range`) scans only the commits a branch adds,
  starting from the merge base so a moving base branch is never blamed on the
  change. This is what lets a repository with pre-existing findings adopt
  Klarion without every pull request failing on somebody else's leak.
- **A persistent verdict cache.** `ai.cache_path` / `--cache-path` keeps
  adjudicated verdicts between runs, keyed by a one-way hash of the candidate
  and scoped to `provider:model`. Only the status and confidence are stored —
  never the secret, and never the model's written reason, which quotes the value
  it describes. CI stops re-paying for unchanged code; a pull request pays only
  for the candidates it introduces.
- **The GitHub Action now behaves like the rest of the ecosystem.** New inputs
  `scan-mode` (`auto|diff|full|history`, defaulting to diff on `pull_request`
  and full elsewhere), `base`, `head`, `cache`, `cache-path` and
  `baseline-file`. The verdict cache is restored and saved via `actions/cache`
  automatically.
- `--baseline` and `--cache-path` flags on `scan` and `git`, so CI can point at
  these files without generating a config file. `git` also gained `--ai-mode`
  and `--show-suppressed` for parity with `scan`.

### Security



- **The API key is now resolved per provider.** `config.Default()` set
  `api_key_env = "ANTHROPIC_API_KEY"` for every provider, so a config that only
  said `provider = "openai"` authenticated against `api.openai.com` with the
  operator's Anthropic key. The variable is now derived from the provider
  (`anthropic` → `ANTHROPIC_API_KEY`, `openai` → `OPENAI_API_KEY`; ollama and
  claude-cli need none), with `ai.api_key_env` as an explicit override.
- **Releases are signed.** `checksums.txt` is signed with keyless cosign;
  `scripts/install.sh` verifies the signature when cosign is on PATH and says so
  when it cannot. A checksum served from the same release it verifies proves
  integrity, not provenance.
- **CI gained `govulncheck` and `gosec`**, and all GitHub Actions are pinned to
  commit SHAs rather than mutable tags.

### Fixed

- **Klarion's own state files are no longer scanned as source.** The verdict
  ledger and the baseline are full of hex digests, which read as high-entropy
  tokens: each run reported the previous run's bookkeeping as fresh secrets, and
  the count grew every time. `.klarion/**` and `.klarion-baseline.json` are now
  ignored by default.
- **The Action installed the wrong scanner.** `version` defaulted to the literal
  string `v0.1.0`, so `uses: 0x1Adi/Klarion@v1.2.3` still downloaded the v0.1.0
  binary. It now resolves from the action ref the caller pinned.
- **Real secrets were silently dropped by the offline verifier.** The
  test/example/docs check matched its markers as substrings of the file path and
  of surrounding code, so `api/latest/config.go` counted as a test path
  (`latest` contains `test`), as did any candidate within three lines of the
  word `specify` or an `example.com` URL. Such candidates were returned as
  `false_positive` at confidence 0.75 — above `min_confidence` — and dropped
  from the report entirely. Matching is now anchored to whole path segments and
  file-name tokens, and only value-describing markers are matched against
  surrounding code. On leaky-repo this raises risk-file recall from 0.55 to 0.62
  with the flask and rails corpora still at zero false positives. Note that these
  suppressors were tuned on those same two corpora and do not generalize; the
  no-AI path is a degraded mode, not a supported configuration
  (see `benchmark/REPORT.md` §12).
- **The Anthropic request could be rejected outright.** The structured-output
  schema sent `minimum`/`maximum` on `confidence`, which the Messages API does
  not accept; `max_tokens` was also fixed at 1024 regardless of batch size, so a
  large batch truncated mid-JSON. Bounds are removed (`clampConfidence` enforces
  the range on the way back) and the budget now scales with the batch.
- **Provider calls now retry transient failures** (429, 408, 5xx and connection
  errors) up to three attempts with exponential backoff, honoring `Retry-After`.
  Previously a single rate-limit blip left a whole batch unverified while the
  scan still reported success.
- **`klarion protect` honors `core.hooksPath`.** In repositories using husky,
  pre-commit, or a corporate hook template, the hook was installed into
  `.git/hooks`, where git never looks — reporting success while protecting
  nothing.
- README documented `klarion git --all`; the flag is `--history`.
- The GitHub Action's SARIF upload requires `security-events: write`, which the
  usage examples did not mention — the scan ran, then the upload failed the job.
- `internal/config` no longer keeps compiled globs in a package-level map keyed
  by pointer, which grew unboundedly across config loads and would race if two
  configs compiled concurrently.

### Changed

- **AI adjudication runs batches in parallel** (`ai.max_concurrency`, default 4)
  instead of strictly sequentially, so latency no longer scales linearly with
  the number of candidates. `Verifier` implementations must be concurrency-safe.
- The verdict cache is explicitly process-local; its unused on-disk persistence
  was removed rather than wired up, because verdict `reason` text is
  model-authored and routinely quotes the candidate it describes.
- `cmd/klarion` has test coverage for the first time, focused on the PreToolUse
  hook's allow/deny/ask decisions and its fail-open and fail-closed paths.

Initial `0.1.0` feature set — the first public release of Klarion, an AI-native
secret scanner combining Rényi-entropy detection with LLM adjudication.

### Added

- **Two-stage detection pipeline.**
  - Stage 1 (`internal/detect`): a fast, deterministic pass combining a curated
    keyword-gated rule engine with a generic normalized-Rényi-entropy sweep over
    high-entropy tokens. Emits candidate findings with stable fingerprints,
    fixed-width redaction, and redacted context snippets.
  - Stage 2 (`internal/verify`): AI adjudication of every candidate with its
    surrounding code context, returning `secret` / `false_positive` /
    `uncertain` verdicts with a confidence score.
- **Normalized Rényi entropy engine** (`internal/entropy`): configurable order α
  (default α = 2, collision entropy; α → 1 recovers Shannon), character-class
  classification, and a closed-form `ExpectedCollision` normalizer that makes a
  single threshold portable across token lengths and alphabets. Scores clamp to
  `[0, 1.25]`.
- **Curated built-in ruleset** (`internal/rules`) with a keyword prescreen,
  per-rule length/allowlist/entropy guards, and severity/tags — plus
  user-defined custom rules via config. (Starter rules shipped; full catalog per
  DESIGN §12 in progress.)
- **AI verifiers**: Anthropic (default, model `claude-haiku-4-5`), any
  OpenAI-compatible endpoint, and Ollama for local/offline use. One of these is
  required — the offline heuristic that runs when none is reachable exists to
  keep the process from crashing, not to produce usable results. Batching,
  verdict caching, structured JSON outputs, and a fail-safe `on_error = keep`
  policy.
- **False-positive filtering**: confident `false_positive` verdicts
  (`confidence ≥ min_confidence`) are demoted to a suppressed list; `uncertain`
  is always treated as a secret.
- **Surfaces**, all from one binary:
  - Standalone CLI: `scan`, `git` (staged + `--all` history), `protect`,
    `hook`, `mcp`, `rules`, `baseline`, `version`.
  - Git pre-commit integration (`klarion protect` + `internal/git` diff parsing).
  - Claude Code PreToolUse hook (`Write|Edit|MultiEdit` and secret-bearing
    `Bash`) with `deny`/`ask` decisions fed back to the agent.
  - MCP server exposing `scan_text`, `scan_file`, and `verify_finding`.
  - Claude Code plugin bundling the hook and MCP server (`claude-plugin/`).
  - GitHub Actions and GitLab CI workflows with SARIF/JUnit/GitLab reports.
- **Configuration** (`internal/config`): layered `.klarion.toml` with discovery
  (`--config` → `$KLARION_CONFIG` → walk-up), strict unknown-key rejection,
  tuned production defaults, gitignore-like glob matching, and allowlists
  (paths, secret regexes, fingerprints, stopwords).
- **Privacy & security guarantees**: raw secrets are never serialized or logged;
  reports emit only fixed-width redacted masks; fingerprints hash the secret;
  inline `klarion:allow` / `gitleaks:allow` markers; baseline suppression;
  `send_secret = false` for redacted-only AI requests.
- **Reporting** (`internal/report`): `text`, `json`, `sarif`, `junit`, and
  `gitlab` output formats, with optional suppressed-finding visibility.
- **Exit-code contract**: `0` clean, `1` findings, `2` operational error.
- **Tooling**: `Makefile` (build/install/test/lint/fmt/vet/tidy/snapshot/
  scan-self) with version metadata injected at link time, MIT license, and a
  self-dogfooding `.klarion.toml`.

[0.1.0]: https://github.com/0x1Adi/Klarion/releases/tag/v0.1.0
