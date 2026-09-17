# Privacy

Klarion runs on your machine or in your own CI. The Klarion authors collect no
data: there is no telemetry, no analytics and no account.

## What leaves your machine

Only what you configure. With an AI model set, Klarion sends each candidate to
that model's provider: the value, its file path and a few nearby lines. The
provider's own privacy policy applies. Set `send_secret = false` under `[ai]` to
send the value redacted. With a local Ollama model, or with no model, nothing is
sent anywhere.

Installing Klarion downloads it from GitHub. The GitHub Action uploads findings
to your repository's Security tab only if `upload-sarif` is on. Values in
reports are masked unless you turn that off (`redact = false`).

## What is stored

A verdict cache on your machine or in your CI cache: a one-way hash and a status
per candidate. It holds no secret values and no model text.

## Contact

Open an issue at https://github.com/0x1Adi/Klarion/issues, or report a security
problem privately as described in SECURITY.md.
