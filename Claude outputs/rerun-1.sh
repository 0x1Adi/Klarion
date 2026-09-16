#!/usr/bin/env bash
# Re-measure the four unseen corpora on the current build, with a real model.
#
#   GROQ_API_KEY=gsk_... ./rerun.sh
#
# Note: no `set -e`. klarion exits 1 when it finds something and 2 on a real
# error, so treating any non-zero exit as fatal aborts the run after the first
# corpus -- which is exactly what happened the first time.
set -uo pipefail

# Provider is switchable because the numbers are model-specific: whatever you
# measure with is what you can honestly claim.
#
#   PROVIDER=claude-cli MODEL=haiku ./rerun.sh     # logged-in Claude CLI, no key
#   PROVIDER=ollama MODEL=gemma4:latest ./rerun.sh # local, no quota, weaker model
#   GROQ_API_KEY=... ./rerun.sh                    # hosted, rate-limited
PROVIDER="${PROVIDER:-openai}"
MODEL="${MODEL:-openai/gpt-oss-20b}"
BASE_URL="${BASE_URL:-https://api.groq.com/openai/v1}"
if [ "$PROVIDER" = "claude-cli" ]; then
  MODEL="${MODEL:-haiku}"
  BASE_URL=""
  command -v claude >/dev/null || { echo "claude CLI not on PATH"; exit 1; }
elif [ "$PROVIDER" = "ollama" ]; then
  MODEL="${MODEL_OVERRIDE:-$MODEL}"
  BASE_URL="${BASE_URL_OVERRIDE:-http://localhost:11434/v1}"
else
  : "${GROQ_API_KEY:?set GROQ_API_KEY (or PROVIDER=ollama MODEL=... for local)}"
fi
# One local model on one GPU serialises anyway: N concurrent requests each take
# N times longer for the same throughput. Hosted APIs benefit from parallelism.
if [ "$PROVIDER" = "ollama" ] || [ "$PROVIDER" = "claude-cli" ]; then
  CONCURRENCY="${CONCURRENCY:-1}"
else
  CONCURRENCY="${CONCURRENCY:-4}"
fi
ROOT="${ROOT:-$HOME/klarion-bench}"
REPO="${REPO:-$HOME/ai-project/secret-detector-ai}"
mkdir -p "$ROOT"

echo "==> provider=$PROVIDER model=$MODEL concurrency=$CONCURRENCY"
echo "==> building klarion from $REPO"
( cd "$REPO" && go build -trimpath -o "$ROOT/klarion" ./cmd/klarion ) || exit 1

: > "$ROOT/neutral.toml"
cat > "$ROOT/ai.toml" <<TOML
[ai]
mode = "on"
provider = "$PROVIDER"
model = "$MODEL"
base_url = "$BASE_URL"
api_key_env = "GROQ_API_KEY"
max_batch = 10
max_concurrency = $CONCURRENCY
timeout_seconds = 300
on_error = "fail"
filter_false_positives = true
min_confidence = 0.6
# Verdicts persist across runs, keyed by a hash of the candidate. Without this
# a run that dies on a rate limit throws away everything it already paid for.
cache_path = "$ROOT/verdicts.json"
TOML

for r in spring-projects/spring-boot hashicorp/terraform vercel/next.js symfony/symfony; do
  d="$ROOT/$(basename "$r")"
  [ -d "$d" ] || { echo "==> cloning $r"; git clone -q --depth 1 "https://github.com/$r" "$d"; rm -rf "$d/.git"; }
done

# Runs a scan, streaming klarion's own progress to the terminal. Prints the
# finding count, or ERR:<code>. Exit 0 = clean, 1 = findings, 2+ = error.
count() {
  local dir="$1" cfg="$2" label="$3" rc
  shift 3
  echo "    -- $label" >&2
  "$ROOT/klarion" scan "$dir" --config "$cfg" "$@" --format json \
    >"$ROOT/out.json" 2> >(tee "$ROOT/last.err" >&2)
  rc=$?
  if [ "$rc" -ge 2 ]; then echo "ERR:$rc"; return; fi
  python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("findings") or []))' \
    "$ROOT/out.json" 2>/dev/null || echo "ERR:parse"
}

printf '\n%-14s %10s %10s %8s %8s\n' corpus "no-AI" "AI on" cut time
printf -- '-%.0s' {1..56}; echo
t_off=0; t_ai=0
for name in spring-boot terraform next.js symfony; do
  d="$ROOT/$name"
  echo "==> $name" >&2
  off=$(count "$d" "$ROOT/neutral.toml" "$name no-AI" --ai-mode off)
  s=$(date +%s)
  ai=$(count "$d" "$ROOT/ai.toml" "$name AI")
  secs=$(( $(date +%s) - s ))
  if [[ "$ai" == ERR:* || "$off" == ERR:* ]]; then
    printf '%-14s %10s %10s %8s %7ss\n' "$name" "$off" "$ai" "-" "$secs"
    echo "    $(tail -1 "$ROOT/last.err")"
  else
    printf '%-14s %10s %10s %7s%% %7ss\n' "$name" "$off" "$ai" "$(( 100 - ai*100/(off>0?off:1) ))" "$secs"
    t_off=$((t_off+off)); t_ai=$((t_ai+ai))
  fi
done
printf -- '-%.0s' {1..56}; echo
[ "$t_off" -gt 0 ] && printf '%-14s %10s %10s %7s%%\n' TOTAL "$t_off" "$t_ai" "$(( 100 - t_ai*100/t_off ))"
