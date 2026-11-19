"""Render the gate's public summary file as a markdown pull request comment.

Standard library only. Holds no model-written text. Every string from the
summary is untrusted: it passes through code() or text() before it is printed.
"""
import argparse
import json
import re
import sys
import unicodedata
from urllib.parse import quote

MARKER = "<!-- ai-security-gate-report -->"
MAX_REPORT = 60000
MAX_ROWS = 50
SHORT = 200
LONG = 300

VERDICTS = ("PASS", "BLOCK", "ERROR")
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
TRIAGE_VERDICTS = ("reachable", "not_reachable", "unknown")

SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
                        r"/actions/runs/[0-9]+(/attempts/[0-9]+)?$")
CWE_RE = re.compile(r"^CWE-([0-9]+)$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA(-[0-9a-z]{4}){3}$")

SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._/-")


def _clean(value, limit, at=False):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        value = ""
    value = str(value)
    value = "".join(" " if (c.isspace() or unicodedata.category(c).startswith("C")) else c
                    for c in value)
    value = value[:limit]
    if at:
        value = value.replace("@", "(at)")
    return "".join(c if c in SAFE else f"&#{ord(c)};" for c in value)


def code(value, limit=SHORT):
    return f"<code>{_clean(value, limit)}</code>"


def text(value, limit=LONG):
    return _clean(value, limit, at=True)


def enum(value, known):
    return value if isinstance(value, str) and value in known else code(value)


def num(value):
    return str(value) if type(value) is int else "-"


def _dicts(value):
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _link(label_html, url):
    return f"[{label_html}]({url})"


def id_cell(value):
    if not isinstance(value, str) or not value:
        return "-"
    m = CWE_RE.match(value)
    if m:
        return _link(code(value), f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html")
    if CVE_RE.match(value):
        return _link(code(value), f"https://www.cve.org/CVERecord?id={value}")
    if GHSA_RE.match(value):
        return _link(code(value), f"https://github.com/advisories/{value}")
    return code(value)


def location_cell(file, line, repo, head):
    if not isinstance(file, str) or not file:
        return "-"
    label = f"{file}:{line}" if type(line) is int and line > 0 else file
    if repo and head and type(line) is int and line > 0 and len(file) <= SHORT:
        url = f"https://github.com/{repo}/blob/{head}/{quote(file)}#L{line}"
        return _link(code(label), url)
    return code(label)


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for row in rows[:MAX_ROWS]:
        out.append("| " + " | ".join(row) + " |")
    if len(rows) > MAX_ROWS:
        out.append("")
        out.append(f"and {len(rows) - MAX_ROWS} more; see the summary artifact")
    return out


def _row(entry, kind, repo, head, with_verdict=False):
    if kind == "change":
        ident, package, severity = entry.get("cwe"), "-", enum(entry.get("severity"), SEVERITIES)
        verdict = "-"
    else:
        ident, severity = entry.get("id"), "-"
        package = code(entry.get("package")) if entry.get("package") else "-"
        verdict = enum(entry.get("verdict"), TRIAGE_VERDICTS)
    cells = ["change finding" if kind == "change" else "scanner finding", id_cell(ident), package]
    if with_verdict:
        cells.append(verdict)
    cells += [severity, enum(entry.get("confidence"), CONFIDENCES),
              location_cell(entry.get("file"), entry.get("line"), repo, head)]
    return cells


def _suppressed_row(entry, kind, repo, head):
    sup = entry.get("suppression") if isinstance(entry.get("suppression"), dict) else {}
    ident = entry.get("cwe") if kind == "change" else entry.get("id")
    return [id_cell(ident), location_cell(entry.get("file"), entry.get("line"), repo, head),
            text(sup.get("reason")), code(sup.get("expires"))]


def render(summary, repo=None, run_url=None):
    repo = repo if isinstance(repo, str) and REPO_RE.match(repo) else None
    run_url = run_url if isinstance(run_url, str) and RUN_URL_RE.match(run_url) else None
    head_raw = summary.get("head")
    head = head_raw if isinstance(head_raw, str) and SHA_RE.match(head_raw) else None
    base_raw = summary.get("base")
    base = base_raw if isinstance(base_raw, str) and SHA_RE.match(base_raw) else None

    verdict = summary.get("verdict")
    findings = _dicts(summary.get("findings"))
    triage = _dicts(summary.get("triage"))
    limits = summary.get("limits") if isinstance(summary.get("limits"), dict) else {}
    totals = summary.get("totals") if isinstance(summary.get("totals"), dict) else {}

    def pick(items, ruling):
        return [x for x in items if x.get("ruling") == ruling]

    f_block, f_sup, f_note = (pick(findings, r) for r in ("blocking", "suppressed", "note"))
    t_block, t_sup, t_note = (pick(triage, r) for r in ("blocking", "suppressed", "note"))
    n_block = len(f_block) + len(t_block)

    out = [MARKER, "", f"## AI security gate: {enum(verdict, VERDICTS)}", ""]
    if verdict == "PASS":
        out.append("Nothing blocks this change.")
    elif verdict == "BLOCK":
        out.append(f"{n_block} item(s) block this change. Fix each one, or add a suppression "
                   "with a reason and an expiry date to the gate's config file.")
    elif verdict == "ERROR":
        out.append(f"The review did not finish: {text(summary.get('error'))}. "
                   "The gate blocks on an error.")
        if summary.get("error_request_id"):
            out += ["", f"Request ID of the failed call: {code(summary.get('error_request_id'))}"]
    out.append("")

    changed = summary.get("changed_files")
    parts = [f"Model: {code(summary.get('model_requested'))}"]
    if base and head:
        parts.append(f"{code(base[:7])}..{code(head[:7])}")
    if isinstance(changed, list):
        parts.append(f"{len(changed)} changed file(s)")
    if run_url:
        parts.append(f"[run]({run_url})")
    out += [" | ".join(parts), ""]

    out.append(f"Change findings: {len(f_block)} blocking, {len(f_sup)} suppressed, "
               f"{len(f_note)} notes. Scanner findings triaged: {len(triage)} total, "
               f"{len(t_block)} blocking, {len(t_sup)} suppressed, "
               f"{sum(1 for t in triage if t.get('verdict') == 'not_reachable')} not reachable, "
               f"{sum(1 for t in triage if t.get('verdict') == 'unknown')} unknown.")
    out.append("")

    warnings = []
    if summary.get("notice"):
        warnings.append("Warning: the gate's config came from the change under review.")
    returned, requested = summary.get("model_returned"), summary.get("model_requested")
    if returned is not None and returned != requested:
        warnings.append("Warning: the model that answered differs from the model requested.")
    for s in _dicts(summary.get("expired_suppressions")):
        which = s.get("id") or s.get("path")
        warnings.append(f"Warning: a suppression has expired and no longer applies: "
                        f"{code(which)}, expired on {code(s.get('expires'))}.")
    for w in warnings:
        out += [w, ""]

    if n_block:
        out += ["### Blocking", ""]
        rows = ([_row(f, "change", repo, head) for f in f_block]
                + [_row(t, "scan", repo, head) for t in t_block])
        out += table(["Kind", "CWE or ID", "Package", "Severity", "Confidence", "Location"], rows)
        out.append("")

    if f_sup or t_sup:
        out += ["### Suppressed", ""]
        rows = ([_suppressed_row(f, "change", repo, head) for f in f_sup]
                + [_suppressed_row(t, "scan", repo, head) for t in t_sup])
        out += table(["CWE or ID", "Location", "Reason", "Expires"], rows)
        out.append("")

    notes = f_note + t_note
    out += [f"<details><summary>Not blocking ({len(notes)})</summary>", ""]
    out.append(
        f"A change finding blocks only when its severity is {enum(limits.get('fail_on'), SEVERITIES)} "
        f"or higher, its confidence is {enum(limits.get('min_confidence'), CONFIDENCES)} or higher, "
        "and its file is in the change. A scanner finding of "
        f"{enum(limits.get('triage_min_severity'), SEVERITIES)} severity or higher is sent to triage "
        "and blocks only when judged reachable with the same minimum confidence. "
        "An owner's suppression stops either from blocking.")
    out.append("")
    if notes:
        rows = ([_row(f, "change", repo, head, True) for f in f_note]
                + [_row(t, "scan", repo, head, True) for t in t_note])
        out += table(["Kind", "CWE or ID", "Package", "Verdict", "Severity", "Confidence",
                      "Location"], rows)
        out.append("")
    out += ["</details>", ""]

    out += ["<details><summary>Run details</summary>", ""]
    out.append(f"- Final stop reason: {code(summary.get('final_stop_reason'))}")
    out.append(f"- Model requested: {code(requested)}")
    out.append(f"- Model returned: {code(returned)}")
    out.append(f"- Effort: {enum(limits.get('effort'), ('low', 'medium', 'high', 'xhigh', 'max'))}")
    for key in sorted(k for k in totals if isinstance(k, str)):
        out.append(f"- {code(key)}: {num(totals[key])}")
    out += ["", "</details>", ""]

    out.append("This report holds no model-written text. "
               "The model's reasons are in the evidence file of a local run.")

    result = "\n".join(out) + "\n"
    if len(result) > MAX_REPORT:
        tail = "\n\nThe report was cut at 60000 characters; see the summary artifact.\n"
        result = result[:MAX_REPORT - len(tail)].rsplit("\n", 1)[0] + tail
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("summary")
    ap.add_argument("--repo")
    ap.add_argument("--run-url")
    args = ap.parse_args(argv)
    try:
        with open(args.summary, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError) as e:
        print(f"report.py: cannot read summary: {type(e).__name__}", file=sys.stderr)
        return 2
    if not isinstance(data, dict) or "verdict" not in data:
        print("report.py: summary is not a JSON object with a verdict", file=sys.stderr)
        return 2
    sys.stdout.write(render(data, args.repo, args.run_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
