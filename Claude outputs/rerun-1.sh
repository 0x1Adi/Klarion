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
# Token levers. The system prompt is resent with every batch, so a larger batch
# amortises it; context lines are the dominant per-candidate cost.
# SAMPLE=0.15 scans a seeded random 15% of each corpus instead of all of it.
# Establishing "adjudication removes ~N% of pre-filter output" does not need
# every candidate: at n=400 the 95% interval on a proportion near 0.8 is about
# +/-4 points. The seed is fixed so the sample is reproducible, and whole files
# are sampled so block collapsing still sees complete key material.
SAMPLE="${SAMPLE:-0}"
SEED="${SEED:-1729}"
BATCH="${BATCH:-10}"
CONTEXT_LINES="${CONTEXT_LINES:-5}"
# Reasoning models bill their scratchpad. For a classification task that is pure
# waste: measured on Groq's gpt-oss-20b, reasoning traces dominated token use.
REASONING="${REASONING:-medium}"
ROOT="${ROOT:-$HOME/klarion-bench}"
REPO="${REPO:-$HOME/ai-project/secret-detector-ai}"
mkdir -p "$ROOT"

echo "==> provider=$PROVIDER model=$MODEL concurrency=$CONCURRENCY batch=$BATCH context=$CONTEXT_LINES reasoning=$REASONING sample=$SAMPLE seed=$SEED"
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
max_batch = $BATCH
max_context_lines = $CONTEXT_LINES
reasoning_effort = "$REASONING"
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

# Runs a scan. Klarion writes JSON to a file and its progress straight to the
# terminal; the count is read back from the file afterwards.
#
# Deliberately NOT `$(klarion ... 2> >(tee ...))`. Command substitution waits on
# process substitution, so that form can hang after klarion has already exited
# -- which looks exactly like a stalled scan and cost an evening to find.
run_scan() {
  local dir="$1" cfg="$2" label="$3"
  shift 3
  echo "    -- $label" >&2
  "$ROOT/klarion" scan "$dir" --config "$cfg" "$@" --format json >"$ROOT/out.json"
  local rc=$?
  if [ "$rc" -ge 2 ]; then echo "ERR:$rc" >"$ROOT/count.txt"; return; fi
  python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("findings") or []))' \
    "$ROOT/out.json" >"$ROOT/count.txt" 2>/dev/null || echo "ERR:parse" >"$ROOT/count.txt"
}

# count() keeps the old call shape but reads the result from a file.
count() {
  run_scan "$@"
  cat "$ROOT/count.txt"
}


# Build the sampled tree once per corpus, deterministically.
sample_dir() {
  local src="$1" dst="$2" frac="$3"
  [ -d "$dst" ] && { echo "$dst"; return; }
  python3 - "$src" "$dst" "$frac" "$SEED" <<'PY'
import os, random, shutil, sys
src, dst, frac, seed = sys.argv[1], sys.argv[2], float(sys.argv[3]), int(sys.argv[4])
files = []
for root, dirs, names in os.walk(src):
    dirs[:] = [d for d in dirs if d != ".git"]
    files.extend(os.path.join(root, n) for n in names)
files.sort()                      # os.walk order is not stable across machines
random.Random(seed).shuffle(files)
keep = files[: max(1, int(len(files) * frac))]
for f in keep:
    rel = os.path.relpath(f, src)
    out = os.path.join(dst, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    try:
        shutil.copy2(f, out)
    except OSError:
        pass
print(f"    sampled {len(keep)}/{len(files)} files", file=sys.stderr)
PY
  echo "$dst"
}

printf '\n%-14s %10s %10s %8s %8s\n' corpus "no-AI" "AI on" cut time
printf -- '-%.0s' {1..56}; echo
t_off=0; t_ai=0
for name in spring-boot terraform next.js symfony; do
  d="$ROOT/$name"
  if [ "$SAMPLE" != "0" ]; then
    d=$(sample_dir "$ROOT/$name" "$ROOT/$name-sample-$SAMPLE-$SEED" "$SAMPLE")
  fi
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
