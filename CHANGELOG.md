# Changelog

All notable changes to Klarion are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
