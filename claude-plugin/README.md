# Klarion — Claude Code plugin

Stops Claude Code from writing or committing leaked secrets. It adds:

- **A PreToolUse hook.** Every `Write`, `Edit` and `MultiEdit`, and every `Bash`
  command, is scanned by `klarion hook` before it runs. For `git add` and
  `git commit` it also scans what the command could commit: changed lines of
  tracked files, and untracked files that `.gitignore` does not exclude. If a
  real secret is found, the tool call is **denied** (or you are **asked**, per
  config), and the reason goes back to Claude so it can fix the code. The hook
  never approves a call, so your permission prompts still apply.
- **`/klarion:scan`** to scan the project, or a path, on demand.

Klarion also has an MCP server (`klarion mcp`). It needs a model configured and
exits without one, so the plugin does not start it.

## Prerequisites

Install the `klarion` binary and put it on `PATH`:

```sh
go install github.com/0x1Adi/Klarion/cmd/klarion@latest
```

Or download a binary from the [releases page](https://github.com/0x1Adi/Klarion/releases).

Configure a model. Either set an API key:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
```

or opt in to your Claude Code login in `.klarion.toml` (Klarion never uses it
unless you set this):

```toml
[ai]
provider = "claude-cli"
```

With no model configured, the hook still blocks provider-issued keys (cloud,
VCS, SaaS tokens), lets everything else through, and says it could not judge it.

## What leaves your machine

With a model configured, each candidate is sent to that model's provider: the
value, its file path and a few nearby lines. Set `send_secret = false` under
`[ai]` to send the value redacted. With a local Ollama, or with no model,
nothing leaves your machine.

## When a change goes through unscanned

The hook never blocks your work because of its own problems. If `klarion` is not
installed, fails, or takes longer than 60 seconds, the change goes through. A
commit of many files with many candidates can take longer than that.

The commit scan covers the repository the session runs in. It does not follow
`cd` or `git -C` into another repository, and does not recognise git aliases.

A missing binary is reported, not hidden: each session starts with a notice that
changes are not being scanned, and each change shows "Klarion is not installed,
so this change was NOT scanned". Nobody sees these in a run with no one watching,
such as `claude -p` in CI, so check `which klarion` on those machines.

## False positives

The block message shows each finding's fingerprint and the exact line to add to
`.klarion.toml`:

```toml
[allowlist]
fingerprints = ["37f6cd332ef64f4cb8df8d74d6fbf521"]
```

It tells Claude to ask you first. A prompt-injected agent can still edit
`.klarion.toml` itself, so review changes to that file.

## Install the plugin

This repository is its own marketplace:

```
/plugin marketplace add 0x1Adi/Klarion
/plugin install klarion@klarion
```

## Configuration

Behavior is controlled by `.klarion.toml` in your project (see the main
project README). The hook honors `[hook] block_on` and `[hook] decision`
(`deny` or `ask`), and `fail_open = true` guarantees an internal scanner error
never blocks your work.
