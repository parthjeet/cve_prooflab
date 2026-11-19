#!/usr/bin/env python3
"""Deterministic baseline of the AI security gate: scanner reports in, verdict out, no model.

Usage: baseline.py --repo DIR --base SHA --head SHA [options]
Exit: 0 PASS, 1 BLOCK, 2 ERROR. The last line printed is `SECURITY BASELINE: <verdict>`.
Standard library only. Never prints or writes scanner message text.
"""
import argparse
import json
import sys
from datetime import date
from pathlib import Path

import gate
import scanner

EXIT = {"PASS": 0, "BLOCK": 1, "ERROR": 2}


def safe(value, limit=300):
    """One-line, escaped, bounded text, so no printed value can start a workflow command."""
    return json.dumps(str(value))[1:-1][:limit]


def sup_info(s):
    return {"path": s.path, "id": s.id, "cwe": s.cwe, "reason": s.reason,
            "expires": s.expires.isoformat()} if s else None


def load_reports(config, scanner_report, sarif_reports):
    """Return (dependency findings, code findings, tools) at the config's threshold."""
    deps = scanner.load(scanner_report, config.triage_min_severity) if scanner_report else []
    code = []
    tools = [{**scanner.dep_tool(scanner_report), "kind": "dependency"}] if scanner_report else []
    for path in sarif_reports:
        found, run_tools = scanner.load_sarif(path, config.triage_min_severity)
        code += found
        tools += [{**t, "kind": "code"} for t in run_tools]
    return deps, code, tools


def dep_entry(v, ruling, suppression=None, answer=None):
    """Summary entry of a dependency finding. `answer` is the model's triage entry, if any."""
    e = {"id": v["VulnerabilityID"], "package": v["PkgName"],
         "installed_version": v["InstalledVersion"], "fixed_version": v["FixedVersion"],
         "severity": v["Severity"].lower(), "target": v["Target"],
         "verdict": answer["verdict"] if answer else None,
         "confidence": answer["confidence"] if answer else None,
         "file": answer["file"] if answer else "", "line": answer["line"] if answer else 0,
         "ruling": ruling, "suppression": sup_info(suppression)}
    if answer:
        e["reason"] = answer["reason"]
    return e


def code_entry(f, ruling, suppression=None, answer=None):
    """Summary entry of a code finding. An accepted finding has no key."""
    e = {"key": f.get("key"), "tool": f["tool"], "rule_id": f["rule_id"],
         "severity": f["severity"], "file": f["file"], "line": f["line"],
         "verdict": answer["verdict"] if answer else None,
         "confidence": answer["confidence"] if answer else None,
         "ruling": ruling, "suppression": sup_info(suppression)}
    if answer:
        e["reason"] = answer["reason"]
    return e


def accepted_entries(bl):
    """(triage, scan) entries of the findings the owner accepted."""
    triage = [dep_entry(f, "suppressed", s) for k, f, s in bl.accepted if k == "dependency"]
    scan = [code_entry(f, "suppressed", s) for k, f, s in bl.accepted if k == "code"]
    return triage, scan


def baseline_entries(bl):
    """(triage, scan) entries with no model verdict: open findings block."""
    t_acc, s_acc = accepted_entries(bl)
    return ([dep_entry(v, "blocking") for v in bl.deps_open] + t_acc,
            [code_entry(f, "blocking") for f in bl.code_open] + s_acc)


def scan_line(e, kind):
    if kind == "dependency":
        return f"scan: dependency {safe(e['id'])} {e['severity']} {safe(e['target'])} {e['ruling']}"
    place = f"{safe(e['file'])}:{e['line']}" if e["file"] else "-"
    return f"scan: {safe(e['tool'])} {safe(e['rule_id'])} {e['severity']} {place} {e['ruling']}"


def run_baseline(repo, base_sha, head_sha, scanner_report=None, sarif_reports=(), *,
                 summary_path=None, today=None, config_path=".ai-security-gate.toml"):
    today = today or date.today()
    summary = {"kind": "baseline", "verdict": "ERROR", "error": None, "base": base_sha,
               "head": head_sha, "notice": None, "limits": {}, "scanners": [], "triage": [],
               "scan": [], "expired_suppressions": []}
    try:
        config, summary["notice"] = gate.load_config(repo, base_sha, head_sha, config_path)
        summary["limits"] = {"triage_min_severity": config.triage_min_severity}
        deps, code, summary["scanners"] = load_reports(config, scanner_report, sarif_reports)
        bl = gate.baseline(deps, code, config, today)
        summary["triage"], summary["scan"] = baseline_entries(bl)
        summary["expired_suppressions"] = [sup_info(s) for s in bl.expired]
        summary["verdict"] = "BLOCK" if bl.deps_open or bl.code_open else "PASS"
    except gate.ConfigError as e:
        summary["error"] = f"bad config: {e}"
    except gate.GateError as e:
        summary["error"] = str(e)
    except Exception:
        summary["error"] = "unexpected error"
    lines = [scan_line(e, "dependency") for e in summary["triage"]]
    lines += [scan_line(e, "code") for e in summary["scan"]]
    if summary["error"]:
        lines.append(f"ERROR: {safe(summary['error'])}")
    lines.append(f"SECURITY BASELINE: {summary['verdict']}")
    print("\n".join(lines))
    if summary_path:
        try:
            Path(summary_path).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        except OSError as e:
            print(f"warning: cannot write {summary_path}: {e.strerror}", file=sys.stderr)
    return summary["verdict"]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--config-path", default=".ai-security-gate.toml")
    p.add_argument("--scanner-report")
    p.add_argument("--sarif", action="append", default=[])
    p.add_argument("--summary-path", default="security-baseline-summary.json")
    a = p.parse_args(argv)
    verdict = run_baseline(a.repo, a.base, a.head, a.scanner_report, a.sarif,
                           summary_path=a.summary_path, config_path=a.config_path)
    return EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main())
