CredData benchmark tools for benchmark/REPORT.md section 14 (2026-09-16).

Rebuild the dataset (Linux; CredData commit c09c0c52):
  git clone https://github.com/Samsung/CredData && cd CredData
  cp <klarion>/benchmark/creddata/fetch_partial.py <klarion>/benchmark/creddata/retry_failed.py .
  python3 fetch_partial.py 12        # blobless fetch of labeled files only, ~13 min
  python3 retry_failed.py            # retries connection resets
  python3 download_data.py --skip_download --data_dir data   # CredData's own move + obfuscate

Scan (from CredData/), then score with the scripts in benchmark/creddata/ (they import score.py):
  klarion scan data --no-ai --show-suppressed -f json --config <klarion>/benchmark/creddata/klarion-bench.toml > klarion.json
  gitleaks dir data --report-format json --report-path gitleaks.json --exit-code 0 --no-banner
  detect-secrets scan --all-files data > detect-secrets.json
  python3 score.py <CredData> --selftest
  python3 score.py <CredData> klarion klarion.json gitleaks gitleaks.json detect-secrets detect-secrets.json
  PROD=1 python3 misses.py <CredData> klarion klarion.json [Category]   # misses by category

AI sample: python3 sample.py <CredData> klarion.json <outdir> 7   (seed 7 is the published run)
  copy score_ai.py and klarion-creddata-ai.toml into <outdir>, then from <outdir>:
  klarion scan data --no-ai --show-suppressed -f json --config klarion-creddata-ai.toml --baseline baseline.json > noai.json
  python3 score_ai.py check noai.json      # must print OK: a wrong baseline path is silently empty
  klarion scan data --show-suppressed -f json --config klarion-creddata-ai.toml --baseline baseline.json --cache-path verdicts.cache > ai.json
  python3 score_ai.py score ai.json
Published results: benchmark/results/creddata-detection.jsonl (rows: klarion scan
everything, klarion defaults, klarion no-AI heuristic, gitleaks 8.30, gitleaks 8.16,
detect-secrets 1.5) and benchmark/results/creddata-ai-sample.txt.
