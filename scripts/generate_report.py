#!/usr/bin/env python3
"""Build reports/report.md from the scan files, the JUnit files, and the analysis file.

Usage: generate_report.py
Exit: 0 both gates pass, 1 a gate fails (report still written), 2 input error (no report).
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_scan = load("check_scan")
validate = load("validate")

HEADINGS = ("Observed facts", "Hypotheses", "Checks", "Remediation", "Limitations")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
VERIFY_COMMANDS = """scripts/scan.sh
uv run --python 3.12 --no-project scripts/check_scan.py
uv run --python 3.12 --no-project --with-requirements requirements-dev.txt scripts/validate.py
uv run --python 3.12 --no-project scripts/generate_report.py"""
SETUP_TEXT = (
    "`scripts/validate.py` runs each image in a container whose port is published on "
    "`127.0.0.1` only, and removes the container after the run. `tests/test_regression.py` "
    "sends three GET requests with `http.client`. Each test asserts the safe behavior, so a "
    "failed test on the vulnerable image is the evidence of the flaw. The request reads one "
    "lab marker file with fixed text. No request goes to any other host. The expected outcome "
    "of each test is:"
)


class InputError(Exception):
    pass


def read_analysis(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise InputError(f"{path}: cannot read analysis file: {e}")
    sections = {}
    current = None
    for line in text.splitlines():
        if line.startswith("## "):
            title = line[3:].strip()
            if title not in HEADINGS:
                raise InputError(f"{path}: unexpected heading '{line}'")
            if title in sections:
                raise InputError(f"{path}: heading '## {title}' appears twice")
            sections[title] = []
            current = title
        elif current is not None:
            sections[current].append(line)
    out = {}
    for title in HEADINGS:
        if title not in sections:
            raise InputError(f"{path}: missing heading '## {title}'")
        body = "\n".join(sections[title]).strip("\n")
        if not body.strip():
            raise InputError(f"{path}: section '## {title}' is empty")
        out[title] = body
    return out


def read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise InputError(f"{path}: cannot read JSON: {e}")


def need(value, what):
    if value in (None, ""):
        raise InputError(f"missing {what}")
    return value


def read_timestamp(path):
    try:
        suite = ET.parse(str(path)).getroot()
        if suite.tag != "testsuite":
            suite = suite.find("testsuite")
        stamp = suite.get("timestamp") if suite is not None else None
    except (OSError, ET.ParseError) as e:
        raise InputError(f"{path}: cannot read XML: {e}")
    return need(stamp, f"timestamp in {path}")


def findings(scan, key="Vulnerabilities"):
    for result in scan.get("Results") or []:
        yield from result.get(key) or []


def scan_info(scan, label):
    return {
        "tag": need(scan.get("ArtifactName"), f"ArtifactName in {label} scan"),
        "created": need(scan.get("CreatedAt"), f"CreatedAt in {label} scan"),
        "image_id": need((scan.get("Metadata") or {}).get("ImageID"),
                         f"Metadata.ImageID in {label} scan"),
        "starlette": sorted({p.get("Version") for p in findings(scan, "Packages")
                             if p.get("Name") == check_scan.PACKAGE and p.get("Version")}),
        "has_cve": any(v.get("VulnerabilityID") == check_scan.CVE_ID for v in findings(scan)),
    }


def severity_table(scans):
    lines = ["| Image | Class | " + " | ".join(SEVERITIES) + " | Total |",
             "|---|---|" + "---|" * (len(SEVERITIES) + 1)]
    for label, scan in scans:
        counts = {}
        for result in scan.get("Results") or []:
            cls = result.get("Class") or "unknown"
            row = counts.setdefault(cls, {})
            for v in result.get("Vulnerabilities") or []:
                sev = v.get("Severity") or "UNKNOWN"
                row[sev] = row.get(sev, 0) + 1
        for cls in sorted(counts):
            row = counts[cls]
            cells = [str(row.get(s, 0)) for s in SEVERITIES]
            lines.append(f"| {label} | {cls} | " + " | ".join(cells)
                         + f" | {sum(row.values())} |")
    return lines


def starlette_ids(scan):
    return {v.get("VulnerabilityID") for v in findings(scan)
            if v.get("PkgName") == check_scan.PACKAGE}


def show_ids(ids):
    return ", ".join(f"`{i}`" for i in sorted(ids)) if ids else "none"


def body_cell(body):
    text = body.replace("|", " ").replace("\r", " ").replace("\n", " ")[:80]
    return f"`{text}`"


def gate_word(code):
    return "FAIL" if code == 1 else "PASS"


def generate(reports_dir, analysis_path, out_path):
    reports_dir = Path(reports_dir)
    out_path = Path(out_path)
    vuln_path = reports_dir / "trivy-vulnerable.json"
    patched_path = reports_dir / "trivy-patched.json"
    junit = {v: reports_dir / f"junit-{v}.xml" for v in validate.VARIANTS}

    def clean(text):
        return text.replace(str(reports_dir), "reports")

    scan_buf, val_buf = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(scan_buf):
        scan_codes = [
            check_scan.check_file("vulnerable", vuln_path, check_scan.VULN_TAG,
                                  check_scan.VULN_VERSION, True),
            check_scan.check_file("patched", patched_path, check_scan.PATCHED_TAG,
                                  check_scan.PATCHED_VERSION, False),
        ]
    with contextlib.redirect_stdout(val_buf):
        val_code = validate.judge(junit)
    scan_lines = clean(scan_buf.getvalue()).rstrip("\n")
    val_lines = clean(val_buf.getvalue()).rstrip("\n")
    if 2 in scan_codes or val_code == 2:
        print(scan_lines)
        print(val_lines)
        return 2
    scan_gate = "FAIL" if 1 in scan_codes else "PASS"
    val_gate = gate_word(val_code)

    try:
        analysis = read_analysis(analysis_path)
        vuln = read_json(vuln_path)
        patched = read_json(patched_path)
        version = read_json(reports_dir / "trivy-version.json")
        trivy_version = need(version.get("Version"), "Version in trivy-version.json")
        db_updated = need((version.get("VulnerabilityDB") or {}).get("UpdatedAt"),
                          "VulnerabilityDB.UpdatedAt in trivy-version.json")
        info = {"vulnerable": scan_info(vuln, "vulnerable"),
                "patched": scan_info(patched, "patched")}
        stamps = {v: read_timestamp(junit[v]) for v in validate.VARIANTS}
        results = {v: {r["name"]: r for r in validate.parse_junit(junit[v])}
                   for v in validate.VARIANTS}
    except InputError as e:
        print(e)
        return 2

    code = 0 if scan_gate == "PASS" and val_gate == "PASS" else 1
    out = ["# CVE-2023-29159 validation report", ""]
    if code == 0:
        out.append("RESULT: both gates passed (scan gate PASS, validation gate PASS).")
    else:
        out.append(f"RESULT: FAILED (scan gate {scan_gate}, validation gate {val_gate}). "
                   "The evidence in this report does not support the analysis below.")
    out += ["",
            f"- Trivy version: {trivy_version}",
            f"- Trivy DB UpdatedAt: {db_updated}"]
    for v in validate.VARIANTS:
        out.append(f"- Scan CreatedAt, {v} image: {info[v]['created']}")
    for v in validate.VARIANTS:
        out.append(f"- JUnit timestamp, {v} run: {stamps[v]}")

    # Vulnerability
    out += ["", "## Vulnerability", ""]
    nvd = f"https://nvd.nist.gov/vuln/detail/{check_scan.CVE_ID}"
    hit = next((v for v in findings(vuln)
                if v.get("VulnerabilityID") == check_scan.CVE_ID
                and v.get("PkgName") == check_scan.PACKAGE
                and v.get("InstalledVersion") == check_scan.VULN_VERSION), None)
    out.append(f"- CVE ID: {check_scan.CVE_ID}")
    if hit is None:
        out += [f"- NVD: {nvd}", "", "Not reported in the vulnerable scan."]
    else:
        for vid in hit.get("VendorIDs") or []:
            if str(vid).startswith("GHSA-"):
                out.append(f"- Advisory: https://github.com/advisories/{vid}")
        out += [f"- NVD: {nvd}",
                f"- Package: {check_scan.PACKAGE}",
                f"- Installed version in the vulnerable image: {hit.get('InstalledVersion')}",
                f"- FixedVersion: {hit.get('FixedVersion')}",
                f"- Severity: {hit.get('Severity')}"]

    # Scanner findings
    out += ["", "## Scanner findings (Trivy)", ""]
    for v in validate.VARIANTS:
        i = info[v]
        out += [f"- {v}: tag `{i['tag']}`, image ID `{i['image_id']}`, "
                f"{check_scan.PACKAGE} version {', '.join(i['starlette']) or 'not found'}, "
                f"{check_scan.CVE_ID} present: {'yes' if i['has_cve'] else 'no'}"]
    out += ["",
            "One finding is one entry in `Results[].Vulnerabilities[]` "
            "(one vulnerability ID for one package).", ""]
    out += severity_table([("vulnerable", vuln), ("patched", patched)])
    out += ["", f"{check_scan.PACKAGE} findings in the patched image:", "",
            "| ID | Severity | FixedVersion |", "|---|---|---|"]
    star = sorted((v for v in findings(patched) if v.get("PkgName") == check_scan.PACKAGE),
                  key=lambda v: v.get("VulnerabilityID") or "")
    for v in star:
        out.append(f"| {v.get('VulnerabilityID')} | {v.get('Severity')} | "
                   f"{v.get('FixedVersion')} |")
    vs, ps = starlette_ids(vuln), starlette_ids(patched)
    out += ["",
            f"{check_scan.PACKAGE} IDs in the vulnerable scan and not in the patched scan: "
            f"{show_ids(vs - ps)}",
            "",
            f"{check_scan.PACKAGE} IDs in the patched scan and not in the vulnerable scan: "
            f"{show_ids(ps - vs)}",
            "", "```", scan_lines, "```", f"SCAN GATE: {scan_gate}"]

    # Analysis
    out += ["", "## Analysis (drafted by Claude, from scripts/report_analysis.md)"]
    for title in HEADINGS[:3]:
        out += ["", f"### {title}", "", analysis[title]]

    # Test setup
    out += ["", "## Test setup and scope", "", SETUP_TEXT, "",
            "| Test | vulnerable | patched |", "|---|---|---|"]
    for test, exp in validate.EXPECTED.items():
        out.append(f"| {test} | {exp['vulnerable']} | {exp['patched']} |")

    # Verified results
    out += ["", "## Verified results (pytest, JUnit XML)", "",
            "| Test | vulnerable expected | vulnerable actual | vulnerable status | "
            "vulnerable body | patched expected | patched actual | patched status | "
            "patched body | Row |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for test, exp in validate.EXPECTED.items():
        cells, ok = [test], True
        for v in validate.VARIANTS:
            r = results[v][test]
            ok &= r["outcome"] == exp[v]
            if v == "vulnerable" and test == validate.SIBLING:
                ok &= (r["status"] == validate.MARKER_STATUS
                       and r["body"] == validate.MARKER_BODY)
            cells += [exp[v], r["outcome"], str(r["status"]), body_cell(r["body"] or "")]
        cells.append("MATCH" if ok else "MISMATCH")
        out.append("| " + " | ".join(cells) + " |")
    out += ["", "```", val_lines, "```", f"VALIDATION GATE: {val_gate}"]

    # Remediation
    total = sum(1 for _ in findings(patched))
    out += ["", "## Remediation and verification", "", analysis["Remediation"], "",
            f"Findings in the patched scan: {total} in total, {len(star)} for "
            f"{check_scan.PACKAGE}.", "", "```", VERIFY_COMMANDS, "```"]

    out += ["", "## Limitations and unresolved assumptions", "", analysis["Limitations"], ""]

    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out))
        os.replace(tmp, out_path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return code


def main():
    return generate(ROOT / "reports", ROOT / "scripts" / "report_analysis.md",
                    ROOT / "reports" / "report.md")


if __name__ == "__main__":
    sys.exit(main())
