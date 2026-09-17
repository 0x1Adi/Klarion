# Klarion reference

Everything the [README](../README.md) leaves out: every command, CI setup, the full config, and how
detection works in detail.

## Where you can run it

A secret can leak at several points and no single spot catches all of them. For AI assisted
teams we suggest running the MCP server, the Claude Code hook and the CLI together, since they
cover different moments.

```mermaid
flowchart LR
    A["AI agent<br/>writes code"] --> B{"MCP server<br/>agent asks first"}
    B -->|clean| C["Write / Edit<br/>tool call"]
    B -->|secret found| A
    C --> D{"Claude Code hook<br/>gate on tool use"}
    D -->|denied| A
    D -->|allowed| E["code on disk"]
    E --> F{"pre-commit<br/>klarion git"}
    F -->|blocked| E
    F -->|clean| G["commit"]
    G --> H{"CI<br/>klarion scan"}
    H -->|fails build| G
    H -->|clean| I(["shipped"])

    style B fill:#221e1b,stroke:#b8a4ed,color:#faf7f2
    style D fill:#221e1b,stroke:#ff4d8b,color:#faf7f2
    style F fill:#221e1b,stroke:#e8b94a,color:#faf7f2
    style H fill:#221e1b,stroke:#a4d4c5,color:#faf7f2
    style I fill:#a4d4c5,stroke:#a4d4c5,color:#14110f
```

Four gates, one binary. Each one catches what the previous one cannot.

| Surface | Where it sits | What it catches |
| --- | --- | --- |
| **MCP server**<br>`klarion mcp` | The agent asks before writing | The agent calls `scan_text` on content it is about to emit and fixes itself. Cooperative, not enforced. |
| **Claude Code hook**<br>`klarion hook` | Gate on tool use (`Write`, `Edit`, `MultiEdit`) and secret bearing `Bash` commands | Even if the agent never asks, the tool call gets scanned and denied before it runs. |
| **CLI**<br>`klarion scan`, `klarion git` | CI, audits, git pre-commit | The backstop for anything that slipped through, human written secrets and third party code. |

### CLI, pre-commit, GitHub Actions, GitLab CI and the Claude Code plugin

**CLI**

```sh
klarion scan ./src              # scan a directory tree
klarion git                     # staged changes only
klarion git --base main         # only what this branch adds, for CI on a PR
klarion git --history           # full git history, for an audit
klarion rules list              # inspect the active ruleset
klarion baseline create         # snapshot current findings as accepted
```

**Git pre-commit**

```sh
klarion protect                 # writes .git/hooks/pre-commit
```

The hook runs `klarion git`, and a real leaked secret in staged content aborts the commit.

**GitHub Action**

```yaml
# .github/workflows/secrets.yml
name: secret-scan
on: [push, pull_request]

jobs:
  klarion:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for the SARIF upload
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0       # needed so a PR's base commit is available
      - uses: 0x1Adi/Klarion@v0.3.1
        with:
          fail-on-severity: medium
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

That is the whole configuration. By default the action:

- **scans only what a pull request adds**, and the whole tree on pushes and
  scheduled runs. A repository with pre-existing findings can adopt Klarion
  without every PR going red for somebody else's leak.
- **caches AI verdicts between runs**, so unchanged code is never re-adjudicated
  and a PR pays only for the candidates it introduces.
- **fails if no API key is set** (`ai-mode: on`). Pass `anthropic-api-key:`.
  `ai-mode: auto` continues with a warning and raw entropy output, which is
  too noisy to rely on.
- **installs the scanner matching the tag you pinned**: `@v0.3.1` runs the
  v0.3.1 binary, and `@v0` installs the latest release.

Useful overrides:

```yaml
      - uses: 0x1Adi/Klarion@v0.3.1
        with:
          scan-mode: full          # auto | diff | full | history
          base: ${{ github.event.pull_request.base.sha }}
          baseline-file: .klarion-baseline.json
          cache: "true"
          fail-on-severity: high
          upload-sarif: "false"
```

**GitLab CI**

```yaml
# .gitlab-ci.yml
secret-scan:
  image: golang:1.25
  script:
    - go install github.com/0x1Adi/Klarion/cmd/klarion@latest
    - klarion scan . --format gitlab > gl-secret-detection-report.json
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
```

**Claude Code plugin**

Klarion ships a plugin in `claude-plugin/` that wires up both the hook and the MCP server.
The repository is its own plugin marketplace:

```
/plugin marketplace add 0x1Adi/Klarion
/plugin install klarion@klarion
```

The hook runs `klarion hook --event pre-tool-use` for `Write`, `Edit` and `MultiEdit`, and a
`--bash` variant guards secret bearing shell commands. On a real secret the tool call is
denied, or the user is asked, depending on `[hook] decision`. With no model configured,
the hook blocks provider keys only and says it could not judge the rest. It uses your
Claude Code login only if you set `provider = "claude-cli"`. The MCP server exposes
`scan_text`, `scan_file` and `verify_finding`.

## Adopting it on a repo that already has findings

Two mechanisms, both standard:

**Diff scanning** is the default on pull requests — the build only fails on
secrets the change introduces. Nothing to configure.

**A baseline** freezes what is already there so full-tree scans pass too:

```sh
klarion baseline create          # writes .klarion-baseline.json
git add .klarion-baseline.json && git commit -m "accept existing findings"
```

Anything in the baseline is suppressed; anything new still fails. To permanently
accept one finding instead, copy its `fingerprint` from the JSON report into
`allowlist.fingerprints` in `.klarion.toml`, or put `klarion:allow` on the line.

## What a CI run costs

Stage 1 is local and free. Only stage 2 calls a model, and only for candidates
it has not already judged:

- Verdicts are cached between runs, keyed by a one-way hash of the candidate and
  the code around it, and scoped to the provider, model and prompt. An unchanged file is never re-adjudicated.
- The cached file holds a hash and a status — **no secrets, and not the model's
  written reason**, which quotes the value it describes. It is safe to commit or
  to restore from the Actions cache.
- On a pull request only the candidates in the diff are considered in the first
  place.
- Armored key blocks are collapsed before adjudication, so a 19-line private key
  costs one model call instead of nineteen.

So the steady state is: a PR pays for the new candidates it introduces, and
nothing else. The GitHub Action wires the cache up for you; elsewhere, pass
`--cache-path .klarion/verdicts.json` and persist that file however your CI
persists things.

## Configuration

Klarion reads `.klarion.toml` or `klarion.toml`, found by walking up from the working
directory. `$KLARION_CONFIG` and `--config` override that. Everything layers on top of tuned
defaults, so your config only needs the keys you want to change. Unknown keys are a hard
error, which catches typos.

### Full annotated config

```toml
[scan]
max_file_size_bytes = 1048576      # 1 MiB, larger files are skipped
workers = 0                        # 0 means runtime.NumCPU()
follow_symlinks = false
max_decode_depth = 2               # base64/hex/percent/\u layers decoded and rescanned, 0 disables
ignore_paths = [                   # globs, matched files are never scanned
  ".git/**", "node_modules/**", "vendor/**", "dist/**",
  "*.min.js", "*.lock", "*.png", "*.pdf",
]

[entropy]
enabled = true
alpha = 2.0                        # Rényi order, 2 is collision entropy, 1 is Shannon
min_length = 20                    # clamped to 16 or more
max_length = 512
threshold = 0.88                   # normalized score near a secret-ish keyword
threshold_no_context = 0.95        # stricter when there's no keyword context
require_digit = true               # generic candidates need a digit or base64 symbol

[rules]
# disable = ["generic-high-entropy"]  # turn off built-in rules by ID.
                                      # Shown commented out on purpose: this
                                      # particular ID is the entropy engine.

# [[rules.custom]]                 # example — add your own regex rule
id = "acme-internal-token"
description = "Acme internal service token"
regex = 'acme_(?:live|test)_[A-Za-z0-9]{32}'
secret_group = 0                   # capture group holding the secret, 0 is whole match
keywords = ["acme_"]               # cheap prescreen, regex only runs if present
entropy = 0.6                      # optional normalized entropy floor
min_len = 0
max_len = 0
severity = "critical"              # critical, high, medium or low
tags = ["internal"]

[allowlist]
paths = ["testdata/**", "docs/**", "**/*_test.go"]  # findings here are suppressed
regexes = ['^AKIAIOSFODNN7EXAMPLE$']                # matching secrets get dropped
fingerprints = ["<32-hex-fingerprint>"]             # permanently accept one finding
stopwords = ["acme_demo"]                           # extra placeholder markers

[ai]
mode = "on"                        # default; requires a real verifier. auto silently degrades, off is entropy-only
provider = "anthropic"             # anthropic, openai, ollama or claude-cli
model = "claude-haiku-4-5"         # fast and cheap for classification
base_url = ""                      # override endpoint for OpenAI compatible or Ollama
api_key_env = ""                   # defaults per provider: anthropic ->
                                   # ANTHROPIC_API_KEY, openai -> OPENAI_API_KEY
max_batch = 8                      # findings per model request
max_concurrency = 4                # batches adjudicated in parallel
cache_path = ""                    # persist verdicts between runs; "" disables
timeout_seconds = 45
on_error = "keep"                  # keep leaves them unverified, fail aborts the scan
filter_false_positives = true
min_confidence = 0.6               # confidence needed to suppress a false positive
send_secret = true                 # false sends redacted instead, accuracy drops
max_context_lines = 3

[report]
format = "text"                    # text, json, sarif, junit or gitlab
redact = true
show_suppressed = false

[hook]
fail_open = true                   # internal errors never block the agent or commit
block_on = "low"                   # minimum severity that triggers a deny
decision = "deny"                  # deny or ask

[baseline]
path = ".klarion-baseline.json"
```

### AI providers and privacy

Stage two runs against Anthropic by default. Set `ANTHROPIC_API_KEY` and it uses
`claude-haiku-4-5`, which is fast and cheap for classification.

For any OpenAI compatible endpoint:

```toml
[ai]
provider = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
model = "gpt-4o-mini"
```

For a fully local setup, Ollama defaults `base_url` to `http://localhost:11434/v1`:

```toml
[ai]
provider = "ollama"
model = "llama3.1"
```

The default is `mode = "on"`: no usable verifier is a hard error, not a fallback.
With `mode = "off"`, or `mode = "auto"` and no credentials around, Klarion falls back to a
built in heuristic verifier and never touches the network. That path is a degraded mode, not
a supported configuration — see [Limits](../README.md#limits) for what it costs you.
**Set `mode = "on"`** so the scan fails loudly when a real verifier cannot be built, rather
than quietly handing you entropy noise. If you cannot send code to a hosted provider, point
`provider = "ollama"` at a local model — that is offline *and* adjudicated, and it is the
right answer for air-gapped environments.

**Privacy.** By default (`send_secret = true`) the raw candidate and its surrounding lines go
to the verifier, because the model needs them to tell a live key from a fixture. Set
`send_secret = false` to send only the redacted form, though accuracy drops.

Secrets never reach your reports or logs. Findings serialize to a fixed width mask like
`abcd****wxyz`, context snippets are redacted before they leave the process, and fingerprints
hash the secret rather than storing it.

## Exit codes

| Code | Meaning |
| :--: | --- |
| `0` | Clean, no unsuppressed secrets |
| `1` | Secrets found |
| `2` | Operational error — bad config, I/O, or a verifier failure under `on_error = "fail"` |

## How detection and adjudication work

### Stage 1, the entropy maths

Every line gets a cheap lowercase keyword prescreen first, so only lines containing a rule's
keyword pay for the regex. Matches then run through per rule guards for length bounds,
allowlist regexes, placeholder filters and an optional entropy floor.

Anything the rules miss gets swept by the generic entropy detector. Klarion scores each token
using **Rényi entropy of order α** (default α = 2, also called collision entropy), then
normalizes that score against what you would expect from a uniformly random string of the
same length and character class.

That normalization is the important part. Raw entropy grows with length and alphabet size, so
a fixed bit threshold means nothing across different tokens. The normalized score sits near
**1.0** for machine generated key material and drops off for human text, identifiers and file
paths. One portable threshold then works for a 20 character hex token and a 200 character
base64 blob alike.

The normalizer uses the exact expectation of the empirical collision probability,

```
E[ Σᵢ p̂ᵢ² ] = 1/n + (n-1)/(n·k)
```

for a length `n` sample over a `k` symbol alphabet, which gives a stable closed form baseline
for finite samples. The score is clamped to `[0, 1.25]` to bound sampling noise.

Why Rényi instead of plain Shannon. For α > 1 the entropy is dominated by the most probable
symbols, so it punishes the skewed character distributions of human written text more sharply.
α stays tunable, and α → 1 recovers Shannon exactly.

Tokens sitting near a secret-ish keyword like `password`, `token` or `key` are held to the more
permissive `entropy.threshold` (default `0.88`, severity high). Tokens with no such context
have to clear the stricter `entropy.threshold_no_context` (default `0.95`, severity medium).
UUIDs, git SHAs, content digests in obvious digest context, digit-less identifiers and
placeholder values get filtered out before scoring.

### Between the stages, collapsing armored blocks

A wrapped PEM or PGP block makes every line of its base64 body look like a
high-entropy string, so one credential used to be reported once per line — 19
times for a private key in spring-boot, 175 times for an embedded public key in
terraform's `public_keys.go`. Runs of three or more same-rule findings on
consecutive lines are merged into a single finding carrying an occurrence count.

Eligibility is deliberately narrow: the file is key material by path (`.pem`,
`.key`, `id_rsa`, …), or it contains an armor header anywhere. Armor is evaluated
per file rather than per run, because a context window spans only a few lines and
would leave every run after the first uncollapsed.

A `.env` or YAML file holding several distinct secrets on consecutive lines is
never merged. That would hide real leaks, which costs far more than the noise it
would remove.

Collapsing happens before adjudication, so it removes the duplicate model calls
in the same pass.

### Stage 2, how the AI verdict works

Candidates go out in batches. Each carries the rule that fired and its description,
the file path and line, the value, a capped window of surrounding source, the
entropy score, and three fields that let the model judge without going looking:
`is_test_path`, `block_type` (`key_block` or `single_line`), and `occurrences`.

That last group is the difference between a useful verdict and a useless one.
Handed five lines of base64 from the middle of a key body, a model can only answer
"yes, that is a private key" — correct, and no help. Told it is one key block of
nineteen lines living under `src/test/resources`, it can tell a fixture from a
live credential.

The verifier is given **no tools and no access to the repository**. The payload is
self-contained by design. The Claude CLI provider passes `--disallowedTools`
explicitly: left enabled it runs a full agent loop, re-reading files and shelling
out before ruling, which adds latency, makes verdicts non-deterministic, and hands
an agent shell access to the checkout being scanned.

For each candidate the model returns:

`secret`, a real leaked credential, which fails the scan.

`false_positive`, a placeholder, fixture, docs example or non-secret ID, which gets suppressed
when confidence clears `min_confidence`. A provider-issued key (AWS, GitHub, Stripe and similar) under a test path is
never suppressed this way: a test folder is no evidence that a live key is fake.

`uncertain`, which Klarion treats as a secret. A security tool should fail safe.

If the verifier itself errors, the default `on_error = "keep"` policy retains those
candidates rather than dropping them — failing open is the safer direction for a
security tool. Be aware of what that looks like: **unverified candidates are
reported as findings**, so a provider outage or a rate limit on a large scan
surfaces as a sudden spike of low-quality results. Rate limiting is the common
trigger, not outages; Klarion retries with backoff before giving up. Set
`on_error = "fail"` if you would rather the run stop than report unadjudicated
candidates.

Run `klarion scan . --show-suppressed` to audit everything the AI filtered out. The low false
positive claim is only worth believing if you can see what was hidden.

## How it compares

| | Klarion | gitleaks | trufflehog |
| --- | --- | --- | --- |
| Curated regex rules | yes | yes | yes |
| Entropy detection | normalized Rényi, α tunable | Shannon | Shannon |
| AI adjudication with context | yes | no | no |
| False positive suppression | AI verdict, allowlists, baseline | allowlist and baseline | live credential check |
| Live credential verification | on the roadmap | no | yes, over network |
| Blocks AI agents at write time | yes, MCP and Claude Code hook | no | no |
| Git pre-commit and history | yes | yes | yes |
| CI reports | text, json, SARIF, JUnit, GitLab | SARIF, JSON | JSON |
| Air-gapped mode | yes, local LLM via ollama | yes | partial |
| Single static binary | yes | yes | yes |

## What Klarion does not do

Klarion is a detective control and we would rather be clear about the limits than oversell it.

It does not rotate or revoke anything, so a secret it finds is still live until you rotate it.
Pre-commit and agent hooks raise the cost of leaking a secret, but a determined user can
bypass a local hook and coverage in headless CI depends on your configuration. The structural
fix for a leaked credential is rotation, least privilege and short lived credentials. Klarion
tells you which secrets to rotate first, it does not replace your secrets manager.
