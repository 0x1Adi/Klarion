# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability in Klarion.

Use GitHub's [private vulnerability reporting](https://github.com/0x1Adi/Klarion/security/advisories/new). It goes straight to the maintainers and nothing is public until we publish an advisory.

Include what you found, how to reproduce it, and what an attacker could do with it. If you have a proof of concept, redact any real credentials before sending.

We read every report and will respond as fast as we reasonably can. We'll credit you in the advisory unless you'd rather stay anonymous.

## What counts as a vulnerability

Things we want to hear about:

A way to make Klarion miss a secret it should catch, especially a general bypass rather than one unusual pattern.

A way to make Klarion leak a secret it scanned, through reports, logs, MCP responses, hook output or error messages.

Anything that lets a scanned repository execute code, exfiltrate data or escalate privileges through Klarion. Klarion reads untrusted code, so it treats every input as hostile.

A flaw in the redaction path, the fingerprint hashing or the config loader.

Things that are not vulnerabilities:

A single missed secret pattern or a single false positive. Those are normal bugs, so open a regular issue.

The fact that `send_secret = true` sends candidate values to your configured AI provider. That's documented behaviour and you can turn it off.

## Verifying a release

Release archives are checksummed, and `checksums.txt` is signed with cosign
keyless signing. The checksum alone proves the download arrived intact; the
signature proves it was built by this repository's release workflow, which is
the part that matters if someone can replace the files.

`scripts/install.sh` verifies the checksum always, and the signature too when
cosign is on your PATH. To verify by hand:

```sh
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github\.com/0x1Adi/Klarion/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then check your archive against the verified checksum file with `sha256sum -c`.

## Supported versions

Klarion is pre 1.0. Security fixes land on the latest release. Once 1.0 ships we'll support the current minor version and the one before it.

## Scope of what Klarion protects

Klarion is a detective control and we'd rather be clear about its limits than oversell it.

It finds and adjudicates leaked secrets in code, git history and agent output. It does not rotate or revoke anything, so a secret Klarion finds is still live until you rotate it.

Pre-commit hooks and the Claude Code hook raise the cost of leaking a secret, but a determined user can bypass a local hook, and coverage in headless CI depends on your configuration. Treat them as strong speed bumps rather than guarantees.

The structural fix for a leaked credential is rotation, least privilege and short lived credentials. Klarion tells you which secrets to rotate first, it does not replace your secrets manager.
