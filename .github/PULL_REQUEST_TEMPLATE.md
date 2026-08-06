## What this changes

<!-- One or two lines. What and why. -->

## How it was tested

<!-- Commands you ran, cases you covered. -->

## Detection impact

<!-- Delete this section if the change cannot affect scan results. -->

Does this change what Klarion flags? If yes, run the harness in `benchmark/` and put the before and after numbers here, especially false positives on the clean corpora.

| | Before | After |
| --- | --- | --- |
| False positives (flask + rails) | | |
| Recall (leaky-repo) | | |

## Checklist

- [ ] `make lint test` passes
- [ ] New detection logic has table driven tests, positive and negative
- [ ] No test requires network access
- [ ] No real secrets in code, tests or fixtures
- [ ] Docs updated if behaviour or config changed
