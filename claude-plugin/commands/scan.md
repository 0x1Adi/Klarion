---
description: Scan the working tree (or a given path) for leaked secrets with Klarion
argument-hint: "[path]"
---

Run Klarion against the repository and report any leaked secrets.

Run `klarion scan` on the path the user gave: $ARGUMENTS

If no path was given, run `klarion scan .` to scan the current directory.

Then summarize the findings for the user: for each finding give the file,
line, rule, severity, the AI verdict (real secret vs false positive) with its
confidence, and a concrete remediation (move the value to an environment
variable or secret manager, rotate the exposed credential, and add the value
to `.klarion.toml` allowlist only if it is a confirmed false positive). If the
scan is clean, say so briefly.
