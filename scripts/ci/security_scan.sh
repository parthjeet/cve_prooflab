#!/usr/bin/env bash
# Usage: security_scan.sh OUT_DIR RULES_DIR
#
# Scan the current directory with Trivy and Semgrep. Write three files to OUT_DIR:
# trivy-deps.json, trivy-config.sarif, semgrep.sarif.
#
# The Semgrep rules fall under the Semgrep Rules License v1.0
# (https://semgrep.dev/legal/rules-license). Rule text must not reach the log or an
# uploaded file. The raw SARIF files stay in a temporary directory. sarif_min.py
# copies an allow-list of fields from them into OUT_DIR, and drops the message of
# each Semgrep result.
#
# No tool sets the exit code from findings. A tool that crashes fails the script.
# Policy lives in ai-security-gate/baseline.py.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 OUT_DIR RULES_DIR" >&2
  exit 2
fi

here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$1"
OUT_DIR="$(cd "$1" && pwd)"
RULES_DIR="$(cd "$2" && pwd)"
SCAN_DIR="$(pwd)"

for d in "$OUT_DIR" "$RULES_DIR"; do
  case "$d/" in
    "$SCAN_DIR"/*)
      echo "ERROR: $d lies inside the scanned directory $SCAN_DIR" >&2
      exit 2
      ;;
  esac
done

RAW="$(mktemp -d)"
trap 'rm -rf "$RAW"' EXIT

trivy --version
semgrep --disable-version-check --version

# 1. Dependencies. The patterns find app/requirements-patched.txt and
#    app/requirements-vulnerable.txt. No ignore file or config file from the checkout.
trivy fs --scanners vuln --format json --output "$OUT_DIR/trivy-deps.json" \
  --file-patterns 'pip:requirements-.*\.txt' --ignorefile '' -c '' --secret-config '' .

# 2. Secrets and config. Trivy logs one ERROR line, "Falling back to embedded checks".
#    That line is expected: --skip-check-update turns off the check bundle download.
trivy fs --scanners secret,misconfig --format sarif --output "$RAW/trivy-config.sarif" \
  --skip-check-update --ignorefile '' -c '' --secret-config '' .

# 3. Rule directories. -prune stops a "security" directory inside another from
#    loading a rule twice.
configs=()
while IFS= read -r dir; do
  configs+=(--config "$dir")
done < <(find "$RULES_DIR" -type d -name security -prune -print | LC_ALL=C sort)
if [ "${#configs[@]}" -eq 0 ]; then
  echo "ERROR: no 'security' directory under $RULES_DIR" >&2
  exit 1
fi

# 4. Static analysis. Standard output goes to /dev/null because it carries rule messages.
semgrep scan --metrics=off --disable-version-check --disable-nosem --no-rewrite-rule-ids \
  --x-ignore-semgrepignore-files --quiet --sarif-output="$RAW/semgrep.sarif" \
  "${configs[@]}" . >/dev/null

# 5. Reduce.
python3 "$here/sarif_min.py" "$RAW/trivy-config.sarif" "$OUT_DIR/trivy-config.sarif"
python3 "$here/sarif_min.py" --drop-message "$RAW/semgrep.sarif" "$OUT_DIR/semgrep.sarif"
