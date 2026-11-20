#!/usr/bin/env bash
# Run model-written proof tests against the app in locked-down containers.
# Usage: run_proofs.sh PROOF_DIR OUT_FILE
# Env: APP_IMAGE, RUNNER_IMAGE, APP_PORT, APP_READY_PATH
# The script reads file names only, never file contents.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: run_proofs.sh PROOF_DIR OUT_FILE" >&2
  exit 2
fi
PROOF_DIR="$1"
OUT_FILE="$2"
: "${APP_IMAGE:?}" "${RUNNER_IMAGE:?}" "${APP_PORT:?}" "${APP_READY_PATH:?}"
TIMEOUT="${PROOF_TIMEOUT:-120}"

started=()
cleanup() {
  local c
  for c in ${started[@]+"${started[@]}"}; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  docker rm -f proof_app >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Collect "<n> <file name>" for names that match the pattern, in numeric order.
tests=()
if [ -d "$PROOF_DIR" ]; then
  while IFS= read -r line; do
    tests+=("$line")
  done < <(
    for f in "$PROOF_DIR"/*; do
      base="${f##*/}"
      if [[ "$base" =~ ^test_proof_([0-9]+)\.py$ ]] && [ -f "$f" ]; then
        printf '%s %s\n' "$((10#${BASH_REMATCH[1]}))" "$base"
      fi
    done | sort -n -s
  )
fi

results=""
record() {
  echo "proof $1: $2"
  results+="$1 $2"$'\n'
}

app_up=false
if [ "${#tests[@]}" -gt 0 ]; then
  if docker run -d --name proof_app --network none --cap-drop ALL \
      --security-opt no-new-privileges "$APP_IMAGE" >/dev/null 2>&1; then
    url="http://127.0.0.1:${APP_PORT}${APP_READY_PATH}"
    for _ in $(seq 1 30); do
      if docker run --rm --network container:proof_app --read-only --tmpfs /tmp \
          --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 \
          -e PYTHONDONTWRITEBYTECODE=1 -e READY_URL="$url" "$RUNNER_IMAGE" \
          python -c 'import os, urllib.request; urllib.request.urlopen(os.environ["READY_URL"], timeout=2)' \
          >/dev/null 2>&1; then
        app_up=true
        break
      fi
      sleep 1
    done
  fi
  if [ "$app_up" != true ]; then
    echo "The app did not start within 30 seconds." >&2
  fi
fi

for entry in ${tests[@]+"${tests[@]}"}; do
  n="${entry%% *}"
  name="${entry#* }"
  if [ "$app_up" != true ]; then
    record "$n" error
    continue
  fi
  rc=0
  started+=("proof_test_$n")
  timeout "$TIMEOUT" docker run --rm --name "proof_test_$n" --network container:proof_app --read-only \
    --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    --user 65534:65534 --pids-limit 128 --memory 512m --cpus 1 \
    -e PROOF_BASE_URL="http://127.0.0.1:${APP_PORT}" -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$PROOF_DIR:/proofs:ro" "$RUNNER_IMAGE" \
    python /opt/proof_pytest.py "/proofs/$name" \
    >/dev/null 2>&1 || rc=$?
  case "$rc" in
    10) record "$n" confirmed ;;
    11) record "$n" not_confirmed ;;
    *)
      record "$n" error
      # A timed-out client leaves its container running. Remove it before the next test.
      docker rm -f "proof_test_$n" >/dev/null 2>&1 || true
      ;;
  esac
done

printf '%s' "$results" | jq -R -s '{results: (split("\n") | map(select(length > 0) | split(" ") | {n: (.[0] | tonumber), outcome: .[1]}))}' > "$OUT_FILE"
