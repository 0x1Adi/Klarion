# Installing Klarion's MCP server

This file is for an AI coding agent setting up the Klarion MCP server. A human can follow it too.

Klarion finds leaked secrets in code: API keys, passwords and tokens. The MCP server lets the
agent check content **before** it writes it to disk or commits it.

## 1. Install the binary

With Go 1.25 or newer:

```sh
go install github.com/0x1Adi/Klarion/cmd/klarion@latest
```

Without Go, download the archive for this platform from
<https://github.com/0x1Adi/Klarion/releases/latest>, unpack it, and put `klarion` on `PATH`.

Confirm it works:

```sh
klarion version
```

## 2. Add the server to the client

Add this entry to the MCP settings file. In Cline that is `~/.cline/mcp.json`, or the
**Configure MCP Servers** button in the MCP Servers pane.

```json
{
  "mcpServers": {
    "klarion": {
      "command": "klarion",
      "args": ["mcp"],
      "disabled": false
    }
  }
}
```

**Do not add `klarion` to the client's auto-approve list.** `scan_file` reads any path it is
given, and with no API key configured the result hands the calling agent the candidate value
itself. Auto-approving it lets text the agent happens to read cause a file like
`~/.aws/credentials` to be opened and its contents put in the model's context, with nobody
asked first. Approve each call.

If the editor cannot find `klarion` on its `PATH`, use the absolute path from `which klarion`
(Windows: `where klarion`) as `command`.

## 3. Pick who judges the candidates

**No API key, the default.** Klarion returns each candidate with the same decision rules its
own verifier follows, and the calling agent judges them. The payload says
`adjudicated_by: "calling-agent"` and claims no verdict. Nothing leaves the machine. This is
the normal setup, and nothing more to configure.

**With an API key.** Klarion judges each candidate itself and returns verdicts. Add the key to
the server entry:

```json
"env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
```

Other providers (OpenAI compatible, Ollama, an existing Claude Code login) go in `.klarion.toml`
under `[ai]`. See [docs/reference.md](./docs/reference.md#configuration).

## 4. Verify the install

Restart the client, then ask the agent to call `scan_text` on this content:

```
DB_TOKEN = "9f8c3b1d2e4a5c6b7d8e9f0a1b2c3d4e5f60718293a4b5c6"
```

A working server returns one candidate for that line. Calling `scan_text` on a line like
`api_key = "YOUR_KEY_HERE"` returns none.

## Tools

| Tool | Use it for |
| --- | --- |
| `scan_text` | Check a block of text or code before writing it. |
| `scan_file` | Check a file already on disk before committing it. |
| `verify_finding` | Judge one candidate: real leak or false positive. |

## Notes

- stdio transport only. No network traffic unless an AI provider is configured.
- `scan_file` reads paths on the local machine. It does not upload files anywhere.
- Repository settings, ignore rules and allowlists come from `.klarion.toml` in the scanned
  project. See [docs/reference.md](./docs/reference.md).
- The MCP server is cooperative: it tells the agent what it found, it cannot stop a write.
  To enforce, add the commit hook (`klarion protect`) or the GitHub Action, both in the
  [README](./README.md).
