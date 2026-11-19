"""Read scanner reports and return the findings the gate should triage.

Two formats: one Trivy JSON file (dependency findings) and SARIF 2.1.0 files
(code, secret, and config findings). Standard library only. No network code.
Raises ScannerError (a GateError); the caller maps it to exit code 2 (ERROR).
"""
import json
import re
from urllib.parse import unquote

from gate import GateError, SEVERITIES

MAX_TRIAGE = 25
MAX_SCAN = 25
MAX_MESSAGE = 1000
REQUIRED = ("VulnerabilityID", "PkgName")
OPTIONAL = ("InstalledVersion", "FixedVersion", "Severity", "Title", "Description")
LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}


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


def read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise ScannerError(f"cannot read {what}: {e}") from None


def load(path, min_severity):
    """Return kept findings in report order, deduplicated by (id, package, target)."""
    report = read_json(path, "scanner report")
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise ScannerError("scanner report: SchemaVersion is not 2")
    kept, seen = [], set()
    for result in object_list(report.get("Results"), "Results"):
        target = result.get("Target", "")
        if not isinstance(target, str):
            raise ScannerError("Target must be a string")
        vulns = object_list(result.get("Vulnerabilities"), "Vulnerabilities")
        for v in vulns:
            check_vulnerability(v)
        if result.get("Class") != "lang-pkgs":
            continue
        for v in vulns:
            key = (v["VulnerabilityID"], v["PkgName"], target)
            if key in seen or not at_or_above(v.get("Severity", ""), min_severity):
                continue
            seen.add(key)
            kept.append({**{k: v.get(k, "") for k in REQUIRED + OPTIONAL}, "Target": target})
    return kept


def dep_tool(path):
    """Name and version of the tool that wrote the dependency report."""
    report = read_json(path, "scanner report")
    trivy = report.get("Trivy") if isinstance(report, dict) else None
    version = trivy.get("Version") if isinstance(trivy, dict) else None
    return {"name": "Trivy", "version": version if isinstance(version, str) else ""}


def check_limits(deps_open, code_open):
    if len(deps_open) > MAX_TRIAGE:
        raise ScannerError("limit reached: triage findings")
    if len(code_open) > MAX_SCAN:
        raise ScannerError("limit reached: code scanner findings")


# ---- SARIF ----

def sub(d, key, name):
    """Return d[key] as an object; absent or null gives {}."""
    v = d.get(key)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ScannerError(f"sarif: {name} must be an object")
    return v


def text_or_empty(v):
    return v if isinstance(v, str) else ""


def sarif_severity(result, rule):
    """Normalize to low, medium, high, critical, or None (dropped)."""
    raw = sub(rule, "properties", "rule properties").get("security-severity")
    if isinstance(raw, (int, float, str)) and not isinstance(raw, bool):
        try:
            score = float(raw)
        except ValueError:
            score = None
        if score is not None:
            for floor, name in ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low")):
                if score > floor if floor == 0.0 else score >= floor:
                    return name
    level = result.get("level")
    if level is None:
        level = sub(rule, "defaultConfiguration", "defaultConfiguration").get("level")
    if level == "none":
        return None
    return LEVEL_SEVERITY.get(level, "medium")


def sarif_file(result):
    """Return (file, line) of the first location."""
    locations = result.get("locations")
    if locations is None:
        return "", 0
    if not isinstance(locations, list):
        raise ScannerError("sarif: locations must be a list")
    if not locations:
        return "", 0
    if not isinstance(locations[0], dict):
        raise ScannerError("sarif: location must be an object")
    phys = sub(locations[0], "physicalLocation", "physicalLocation")
    uri = sub(phys, "artifactLocation", "artifactLocation").get("uri")
    line = sub(phys, "region", "region").get("startLine")
    line = line if isinstance(line, int) and not isinstance(line, bool) and line >= 1 else 0
    if uri is None or uri == "":
        return "", line
    if not isinstance(uri, str):
        raise ScannerError("sarif: uri must be a string")
    path = unquote(uri)
    if path.lower().startswith("file:"):
        raise ScannerError("sarif: file: URI not allowed")
    if path.startswith(("/", "\\")) or re.match(r"[A-Za-z]:", path):
        raise ScannerError("sarif: absolute path not allowed")
    while path.startswith("./"):
        path = path[2:]
    if ".." in re.split(r"[/\\]", path):
        raise ScannerError("sarif: '..' in path not allowed")
    return path, line


def load_sarif(path, min_severity):
    """Return (findings, tools) from one SARIF 2.1.0 file."""
    report = read_json(path, "SARIF report")
    if not isinstance(report, dict) or report.get("version") != "2.1.0":
        raise ScannerError("sarif: version is not 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, list) or not all(isinstance(r, dict) for r in runs):
        raise ScannerError("sarif: runs must be a list of objects")
    kept, tools, seen = [], [], set()
    for run in runs:
        driver = sub(sub(run, "tool", "tool"), "driver", "driver")
        name = driver.get("name")
        if not isinstance(name, str) or not name:
            raise ScannerError("sarif: tool.driver.name must be a non-empty string")
        version = text_or_empty(driver.get("version")) or text_or_empty(
            driver.get("semanticVersion"))
        tools.append({"name": name, "version": version})
        rules = driver.get("rules")
        rules = [r if isinstance(r, dict) else {} for r in rules] if isinstance(rules, list) else []
        by_id = {}
        for r in rules:
            if isinstance(r.get("id"), str):
                by_id.setdefault(r["id"], r)
        for result in object_list(run.get("results"), "sarif: results"):
            rule_id = result.get("ruleId")
            if rule_id is None:
                rule_id = sub(result, "rule", "rule").get("id")
            if not isinstance(rule_id, str) or not rule_id:
                raise ScannerError("sarif: result needs a non-empty string ruleId")
            file, line = sarif_file(result)
            kind = result.get("kind")
            if kind is not None and kind != "fail":
                continue
            index = result.get("ruleIndex")
            if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(rules):
                rule = rules[index]
            else:
                rule = by_id.get(rule_id, {})
            severity = sarif_severity(result, rule)
            if severity is None or not at_or_above(severity, min_severity):
                continue
            key = (name, rule_id, file, line)
            if key in seen:
                continue
            seen.add(key)
            message = text_or_empty(sub(result, "message", "message").get("text"))
            kept.append({"tool": name, "tool_version": version, "rule_id": rule_id,
                         "severity": severity, "file": file, "line": line,
                         "message": message[:MAX_MESSAGE]})
    return kept, tools
