"""Read a Trivy JSON report and return the findings the gate should triage.

Standard library only. No network code. Raises ScannerError (a GateError);
the caller maps it to exit code 2 (ERROR).
"""
import json

from gate import GateError, SEVERITIES

MAX_TRIAGE = 25
REQUIRED = ("VulnerabilityID", "PkgName")
OPTIONAL = ("InstalledVersion", "FixedVersion", "Severity", "Title", "Description")


class ScannerError(GateError):
    pass


def object_list(value, name):
    """Return value as a list of objects; absent or null gives []."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
        raise ScannerError(f"{name} must be a list of objects")
    return value


def check_vulnerability(v):
    for key in REQUIRED:
        if not isinstance(v.get(key), str) or not v[key]:
            raise ScannerError(f"{key} must be a non-empty string")
    for key in OPTIONAL:
        if key in v and not isinstance(v[key], str):
            raise ScannerError(f"{key} must be a string")


def at_or_above(severity, min_severity):
    s = severity.lower()
    return s in SEVERITIES and SEVERITIES.index(s) >= SEVERITIES.index(min_severity)


def load(path, min_severity):
    """Return kept findings in report order, deduplicated by (id, package)."""
    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError) as e:
        raise ScannerError(f"cannot read scanner report: {e}") from None
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ScannerError("scanner report: SchemaVersion is not 2")
    kept, seen = [], set()
    for result in object_list(report.get("Results"), "Results"):
        vulns = object_list(result.get("Vulnerabilities"), "Vulnerabilities")
        for v in vulns:
            check_vulnerability(v)
        if result.get("Class") != "lang-pkgs":
            continue
        for v in vulns:
            key = (v["VulnerabilityID"], v["PkgName"])
            if key in seen or not at_or_above(v.get("Severity", ""), min_severity):
                continue
            seen.add(key)
            kept.append({k: v.get(k, "") for k in REQUIRED + OPTIONAL})
    if len(kept) > MAX_TRIAGE:
        raise ScannerError("limit reached: triage findings")
    return kept
