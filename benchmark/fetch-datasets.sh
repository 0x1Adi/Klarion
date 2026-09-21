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

# name          scan-targets  upstream                                            pinned commit
DATASETS=(
  "leaky-repo     leaky         https://github.com/Plazmaz/leaky-repo.git           2e951359cac53addbee56437da3ffb546e3dfe24"
  "fp-flask       flask         https://github.com/pallets/flask.git                36e4a824f340fdee7ed50937ba8e7f6bc7d17f81"
  "fp-rails       rails         https://github.com/rails/rails.git                  52d9587a5e5b0fbda40da7b2c52f2307ed2c12c0"
  # The four unseen ecosystems. Added 2026-09-21 with REPORT §16. Before that they
  # were never pinned anywhere, so §12's numbers could not be re-derived by anyone.
  "fp-spring-boot spring-boot   https://github.com/spring-projects/spring-boot.git  adbbf047320013ee42284d6957293aaf75a56ad7"
  "fp-terraform   terraform     https://github.com/hashicorp/terraform.git          78194be60cdab9c71ea1caf5e5c0b4d96e2c3691"
  "fp-nextjs      next.js       https://github.com/vercel/next.js.git               34433fd12ee8074ea3f47af9f36255c7390d0301"
  "fp-symfony     symfony       https://github.com/symfony/symfony.git              15c65b4d72b128f39265017bcb729888fd342fb3"
)

mkdir -p datasets/scan-targets

for entry in "${DATASETS[@]}"; do
  read -r name short url sha <<<"$entry"
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

  # The harness scans datasets/scan-targets/<short>, NOT the checkout. That copy
  # must have no .git: scanning packed objects would count them as findings.
  # This step used to be manual and undocumented, which is why the four
  # ecosystems were missing from it entirely.
  target="datasets/scan-targets/$short"
  rm -rf "$target"
  mkdir -p "$target"
  git -C "$dir" archive HEAD | tar -x -C "$target"

  echo "    $name @ $(git -C "$dir" rev-parse --short HEAD) -> scan-targets/$short ($(find "$target" -type f | wc -l | tr -d ' ') files)"
done

echo
echo "Done. Corpora are in benchmark/datasets/ and are gitignored on purpose."
echo "Scan targets (no .git) are in benchmark/datasets/scan-targets/."
echo
echo "Run the harness with:"
echo "  python3 benchmark/harness/run_benchmark.py"
echo "  BENCH_DATASETS=spring-boot,terraform,next.js,symfony python3 benchmark/harness/run_benchmark.py   # REPORT §16"
