#!/usr/bin/env bash
# Scan the two local lab images with Trivy and save JSON reports to reports/.
set -euo pipefail

TRIVY_VERSION="0.76.2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS_DIR="$REPO_ROOT/reports"

TMP_FILES=()
cleanup() {
  if ((${#TMP_FILES[@]})); then
    rm -f -- "${TMP_FILES[@]}"
  fi
}
trap cleanup EXIT

die() {
  echo "error: $*" >&2
  exit 1
}

# Checks
command -v trivy >/dev/null 2>&1 || die "trivy not found on PATH. Install Trivy $TRIVY_VERSION."

found_line="$(trivy --version | grep -m1 '^Version:')" || die "cannot read the Version line from 'trivy --version'."
found_version="${found_line#Version:}"
found_version="${found_version#"${found_version%%[![:space:]]*}"}"
found_version="${found_version%"${found_version##*[![:space:]]}"}"
if [[ "$found_version" != "$TRIVY_VERSION" ]]; then
  {
    echo "error: Trivy version mismatch."
    echo "Expected: $TRIVY_VERSION"
    echo "Found: $found_version"
    echo "The lab pins Trivy; to change the version, edit TRIVY_VERSION in scripts/scan.sh and the CI install step together, then rerun the scan gate."
  } >&2
  exit 1
fi

for v in vulnerable patched; do
  docker image inspect "cve_prooflab:$v" >/dev/null 2>&1 \
    || die "image cve_prooflab:$v not found locally. This script does not build or pull images."
done

mkdir -p "$REPORTS_DIR"

# Scans
tmp_vulnerable="$(mktemp "$REPORTS_DIR/.trivy-vulnerable.XXXXXX")"
TMP_FILES+=("$tmp_vulnerable")
tmp_patched="$(mktemp "$REPORTS_DIR/.trivy-patched.XXXXXX")"
TMP_FILES+=("$tmp_patched")
for v in vulnerable patched; do
  tmp_var="tmp_$v"
  trivy image --image-src docker --scanners vuln --list-all-pkgs --no-progress \
    --format json --output "${!tmp_var}" "cve_prooflab:$v"
done

# Version record
tmp_version="$(mktemp "$REPORTS_DIR/.trivy-version.XXXXXX")"
TMP_FILES+=("$tmp_version")
trivy version --format json >"$tmp_version"
if ! jq -e '.Version and .VulnerabilityDB.UpdatedAt' "$tmp_version" >/dev/null 2>&1; then
  echo "warning: expected keys .Version and .VulnerabilityDB.UpdatedAt not both present; actual keys: $(jq -c 'keys' "$tmp_version" 2>/dev/null || echo unreadable)" >&2
fi

# Move all three into place only after every step has succeeded
mv -f -- "$tmp_vulnerable" "$REPORTS_DIR/trivy-vulnerable.json"
mv -f -- "$tmp_patched" "$REPORTS_DIR/trivy-patched.json"
mv -f -- "$tmp_version" "$REPORTS_DIR/trivy-version.json"

for f in trivy-vulnerable.json trivy-patched.json trivy-version.json; do
  echo "$REPORTS_DIR/$f"
done
