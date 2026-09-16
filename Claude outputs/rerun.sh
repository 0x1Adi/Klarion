#!/usr/bin/env bash
# Re-measure the four unseen corpora on the current build, with a real model.
#
#   GROQ_API_KEY=gsk_... ./rerun.sh
#
# Note: no `set -e`. klarion exits 1 when it finds something and 2 on a real
# error, so treating any non-zero exit as fatal aborts the run after the first
# corpus -- which is exactly what happened the first time.
set -uo pipefail

: "${GROQ_API_KEY:?set GROQ_API_KEY}"
ROOT="${ROOT:-$HOME/klarion-bench}"
REPO="${REPO:-$HOME/ai-project/secret-detector-ai}"
mkdir -p "$ROOT"

echo "==> building klarion from $REPO"
( cd "$REPO" && go build -trimpath -o "$ROOT/klarion" ./cmd/klarion ) || exit 1

: > "$ROOT/neutral.toml"
cat > "$ROOT/ai.toml" <<'TOML'
[ai]
mode = "on"
provider = "openai"
model = "openai/gpt-oss-20b"
base_url = "https://api.groq.com/openai/v1"
api_key_env = "GROQ_API_KEY"
max_batch = 10
on_error = "fail"
filter_false_positives = true
min_confidence = 0.6
TOML

for r in spring-projects/spring-boot hashicorp/terraform vercel/next.js symfony/symfony; do
  d="$ROOT/$(basename "$r")"
  [ -d "$d" ] || { echo "==> cloning $r"; git clone -q --depth 1 "https://github.com/$r" "$d"; rm -rf "$d/.git"; }
done

# Prints the finding count, or ERR:<code> when klarion genuinely failed.
# Exit 0 = clean, 1 = findings, 2+ = error.
count() {
  local dir="$1" cfg="$2" json rc
  shift 2
  json=$("$ROOT/klarion" scan "$dir" --config "$cfg" "$@" --format json 2>"$ROOT/last.err")
  rc=$?
  if [ "$rc" -ge 2 ]; then echo "ERR:$rc"; return; fi
  printf '%s' "$json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("findings") or []))' 2>/dev/null || echo "ERR:parse"
}

printf '\n%-14s %10s %10s %8s %8s\n' corpus "no-AI" "AI on" cut time
printf -- '-%.0s' {1..56}; echo
t_off=0; t_ai=0
for name in spring-boot terraform next.js symfony; do
  d="$ROOT/$name"
  off=$(count "$d" "$ROOT/neutral.toml" --ai-mode off)
  s=$(date +%s)
  ai=$(count "$d" "$ROOT/ai.toml")
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
