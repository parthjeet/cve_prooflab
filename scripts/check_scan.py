#!/usr/bin/env python3
"""Scan gate: CVE must appear in the vulnerable scan and not in the patched scan.

Usage: check_scan.py [VULN_JSON PATCHED_JSON]
Exit: 0 gate passes, 1 gate fails, 2 input or coverage error.
"""
import json
import sys
from pathlib import Path

CVE_ID = "CVE-2023-29159"
PACKAGE = "starlette"
VULN_VERSION = "0.26.1"
PATCHED_VERSION = "0.27.0"
VULN_TAG = "cve_prooflab:vulnerable"
PATCHED_TAG = "cve_prooflab:patched"

ROOT = Path(__file__).resolve().parent.parent


def entries(report, key):
    for result in report.get("Results") or []:
        yield from result.get(key) or []


def check_file(label, path, tag, version, vulnerable):
    """Return 0 (ok), 1 (gate fail) or 2 (input or coverage error)."""
    print(f"[{label}] {path}")

    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
        if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
            raise ValueError("SchemaVersion is not 2")
    except (OSError, ValueError) as e:
        print(f"  1 valid Trivy JSON: FAIL: {e}")
        return 2
    print("  1 valid Trivy JSON: PASS")

    if report.get("ArtifactName") != tag:
        print(f"  2 artifact name: FAIL: expected {tag}, got {report.get('ArtifactName')!r}")
        return 2
    print(f"  2 artifact name: PASS ({tag})")

    if not any(p.get("Name") == PACKAGE and p.get("Version") == version
               for p in entries(report, "Packages")):
        print(f"  3 coverage: FAIL: {PACKAGE} {version} not in scanned packages")
        return 2
    print(f"  3 coverage: PASS ({PACKAGE} {version} scanned)")

    hits = [v for v in entries(report, "Vulnerabilities")
            if v.get("VulnerabilityID") == CVE_ID]
    if vulnerable:
        hits = [v for v in hits
                if v.get("PkgName") == PACKAGE and v.get("InstalledVersion") == version]
        if not hits:
            print(f"  4 finding: FAIL: {CVE_ID} not reported for {PACKAGE} {version}")
            return 1
        print(f"  4 finding: PASS ({CVE_ID} present; FixedVersion "
              f"{hits[0].get('FixedVersion')}, VendorIDs {hits[0].get('VendorIDs')})")
        return 0
    if hits:
        print(f"  4 finding: FAIL: {CVE_ID} still reported")
        return 1
    print(f"  4 finding: PASS ({CVE_ID} absent)")
    return 0


def main():
    args = sys.argv[1:]
    if len(args) == 0:
        vuln, patched = ROOT / "reports/trivy-vulnerable.json", ROOT / "reports/trivy-patched.json"
    elif len(args) == 2:
        vuln, patched = args
    else:
        print("usage: check_scan.py [VULN_JSON PATCHED_JSON]")
        return 2
    codes = [
        check_file("vulnerable", vuln, VULN_TAG, VULN_VERSION, True),
        check_file("patched", patched, PATCHED_TAG, PATCHED_VERSION, False),
    ]
    return 2 if 2 in codes else max(codes)


if __name__ == "__main__":
    try:
        code = main()
    except Exception as e:  # an uncaught error must not read as a gate failure
        print(f"unexpected error: {e!r}")
        code = 2
    print({0: "SCAN GATE: PASS", 1: "SCAN GATE: FAIL"}.get(code, "SCAN GATE: ERROR"))
    sys.exit(code)
