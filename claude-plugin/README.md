# Klarion — Claude Code plugin

Stops Claude Code from writing or committing leaked secrets. Bundles two
surfaces:

- **PreToolUse hook** — every `Write`/`Edit`/`MultiEdit` and secret-bearing
  `Bash` command (e.g. `git commit`) is scanned by `klarion hook` before it
  runs. If a real secret is detected the tool call is **denied** (or the agent
  is **asked**, per config), with the reason fed back to Claude so it can fix
  the code instead of leaking.
- **MCP server** — exposes `scan_text`, `scan_file`, and `verify_finding`
  tools so the agent can proactively check content it is about to write.

## Prerequisites

Install the `klarion` binary and put it on `PATH`:

```sh
go install github.com/0x1Adi/Klarion/cmd/klarion@latest
# or: brew install 0x1Adi/tap/klarion
```

Set an API key. Klarion requires a model to adjudicate candidates; without one
the hook falls back to raw entropy output and will flag ordinary identifiers,
certificates and vendored code:

```sh
export ANTHROPIC_API_KEY=sk-ant-...
```

## Install the plugin

From a Claude Code marketplace that includes this plugin, or locally:

```
/plugin install klarion
```

## Configuration

Behavior is controlled by `.klarion.toml` in your project (see the main
project README). The hook honors `[hook] block_on` and `[hook] decision`
(`deny` or `ask`), and `fail_open = true` guarantees an internal scanner error
never blocks your work.
