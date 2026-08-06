# Contributing to Klarion

Thanks for helping out. Klarion is a security tool, so the bar for correctness is high, but the workflow itself is simple.

## Getting set up

You need Go 1.25 or newer.

```sh
git clone https://github.com/0x1Adi/Klarion && cd klarion
make build
make lint test
```

`make lint test` has to pass before anything gets merged. If it fails on a clean checkout, that's a bug worth reporting on its own.

## Ground rules

**No test may require network access.** Tests run in CI and on machines without API keys. If you're testing AI adjudication, use the fake verifier in the test helpers rather than calling a real provider.

**New detection logic needs table driven tests.** Add both a positive case and a negative case. A rule that catches real secrets but also flags every UUID is worse than no rule.

**False positives are bugs.** Klarion's whole pitch is that its alerts are worth reading. If a change makes the scanner noisier on real code, it needs a very good reason.

**Never commit a real secret**, not even an expired one, and not in test fixtures. Use obviously fake values like `AKIAIOSFODNN7EXAMPLE`. Klarion scans its own repo in CI, so it will catch you.

## Adding a rule

Read [DESIGN.md](./DESIGN.md) first for the architecture and the existing ruleset catalog. Rules live in `internal/rules`. Each one needs an ID, a description, a regex, and keywords for the prescreen. Keywords matter for performance, since the regex only runs on lines that contain one.

Before you open the PR, run the benchmark harness in `benchmark/` and check that your rule didn't add false positives to the clean corpora. Include the before and after numbers in your PR description.

## Commits and PRs

Keep commits focused on one thing. Write a subject line that says what changed and why, and explain any tradeoffs in the body.

For the PR, describe what you changed, how you tested it, and whether it affects detection accuracy. If it does, include benchmark numbers.

## Reporting bugs

Open an issue with the version (`klarion version`), your OS, the config you were using, and a minimal example that reproduces it. If it's a false positive or a missed secret, a redacted snippet of the code that triggered it helps a lot.

Do not open a public issue for a security vulnerability in Klarion itself. See [SECURITY.md](./SECURITY.md).

## Questions

Open a discussion or an issue. If you're planning something large, ask before you build it so we can agree on the approach first.
