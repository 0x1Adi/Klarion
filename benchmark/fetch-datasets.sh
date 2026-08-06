#!/usr/bin/env bash
# Fetch the benchmark corpora.
#
# These are third party repositories, so we pin them to the exact commits used
# for the published run in REPORT.md rather than committing 121 MB into this
# repo. Pinning matters: if flask or rails move, your numbers stop being
# comparable to the ones we published.
#
#   ./benchmark/fetch-datasets.sh
#
# Re-running is safe. Existing checkouts are reset to the pinned commit.

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p datasets

# name        upstream                                      pinned commit
DATASETS=(
  "leaky-repo https://github.com/Plazmaz/leaky-repo.git      2e951359cac53addbee56437da3ffb546e3dfe24"
  "fp-flask   https://github.com/pallets/flask.git           36e4a824f340fdee7ed50937ba8e7f6bc7d17f81"
  "fp-rails   https://github.com/rails/rails.git             52d9587a5e5b0fbda40da7b2c52f2307ed2c12c0"
)

for entry in "${DATASETS[@]}"; do
  read -r name url sha <<<"$entry"
  dir="datasets/$name"

  if [[ -d "$dir/.git" ]]; then
    echo "==> $name, updating to $sha"
    git -C "$dir" fetch --quiet origin "$sha" 2>/dev/null || git -C "$dir" fetch --quiet origin
  else
    echo "==> $name, cloning"
    rm -rf "$dir"
    git clone --quiet "$url" "$dir"
  fi

  git -C "$dir" checkout --quiet "$sha"
  echo "    $name @ $(git -C "$dir" rev-parse --short HEAD)"
done

echo
echo "Done. Corpora are in benchmark/datasets/ and are gitignored on purpose."
echo "Run the harness with: python3 benchmark/harness/run_benchmark.py"
