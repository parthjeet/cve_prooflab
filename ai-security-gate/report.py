"""Render the gate's public summary files as a markdown pull request comment.

Standard library only. The inputs are the AI review summary and the scanner
baseline summary. final_verdict() combines them into the result of the whole
gate. Model-written text appears only when the AI summary holds "details": true,
and only in the fields title, impact, fix, and reason. Neither summary holds
scanner message text. Every string from either summary is untrusted: it passes
through code() or text() before it is printed.
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
DETAIL = 500
MAX_BLOCKS = 20
FIX_LINE = ("upgrade the package to a release that fixes this advisory, "
            "or remove the code path that reaches it.")

VERDICTS = ("PASS", "BLOCK", "ERROR")
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
TRIAGE_VERDICTS = ("reachable", "not_reachable", "unknown")
SCAN_VERDICTS = ("true_positive", "false_positive", "unknown")
NOT_REVIEWED = "not reviewed"
CODE_FIX_LINE = ("change the code so that the rule no longer applies. If the finding is "
                 "wrong for this code, the repository owner can accept it in the gate's "
                 "config file.")

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


def _label(file, line):
    if not isinstance(file, str) or not file:
        return "-"
    return f"{file}:{line}" if type(line) is int and line > 0 else file


def _sev(entry):
    value = entry.get("severity")
    return "-" if value is None else enum(value, SEVERITIES)


def _conf(entry):
    value = entry.get("confidence")
    return "-" if value is None else enum(value, CONFIDENCES)


def _parts(entry, kind, repo, head):
    """The cells that the blocking, cleared, and accepted tables share.
    kind is "change", "dep" (dependency finding), or "code" (code scan finding)."""
    if kind == "change":
        return {"source": "Code change", "ident": id_cell(entry.get("cwe")), "package": "-",
                "severity": enum(entry.get("severity"), SEVERITIES), "verdict": "-",
                "location": location_cell(entry.get("file"), entry.get("line"), repo, head)}
    verdict = entry.get("verdict")
    if kind == "dep":
        # The model's file and line only when it found the advisory reachable.
        if verdict == "reachable" and entry.get("file"):
            location = location_cell(entry.get("file"), entry.get("line"), repo, head)
        else:
            location = location_cell(entry.get("target"), None, repo, head)
        return {"source": "Dependency scan", "ident": id_cell(entry.get("id")),
                "package": code(entry.get("package")) if entry.get("package") else "-",
                "severity": _sev(entry), "location": location,
                "verdict": NOT_REVIEWED if verdict is None else enum(verdict, TRIAGE_VERDICTS)}
    return {"source": f"Code scan {code(entry.get('tool'))}",
            "ident": id_cell(entry.get("rule_id")), "package": "-", "severity": _sev(entry),
            "verdict": NOT_REVIEWED if verdict is None else enum(verdict, SCAN_VERDICTS),
            "location": location_cell(entry.get("file"), entry.get("line"), repo, head)}


def _row(entry, repo, head):
    """Row of the non-blocking table, which lists change findings only."""
    return ["change finding", id_cell(entry.get("cwe")), "-", "-",
            enum(entry.get("severity"), SEVERITIES), _conf(entry),
            location_cell(entry.get("file"), entry.get("line"), repo, head)]


def detail(entry, key, limit):
    """Escaped model text of one field, or None when it is not a non-empty string."""
    value = entry.get(key)
    return text(value, limit) if isinstance(value, str) and value.strip() else None


def _blocking_row(n, entry, kind, repo, head):
    p = _parts(entry, kind, repo, head)
    return [str(n), p["source"], p["severity"], p["ident"], p["package"], p["verdict"],
            _conf(entry), p["location"]]


def _cleared_row(entry, kind, repo, head):
    p = _parts(entry, kind, repo, head)
    return [p["source"], p["ident"], p["package"], p["severity"], p["verdict"], _conf(entry),
            p["location"]]


def _block(n, entry, kind):
    if kind == "change":
        title = detail(entry, "title", SHORT)
        out = [f"**{n}. {title or 'Code change finding'}**", ""]
        for label, key in (("Impact", "impact"), ("Recommended fix", "fix")):
            value = detail(entry, key, DETAIL)
            if value:
                out.append(f"- {label}: {value}")
        return out + [""]
    if kind == "dep":
        out = [f"**{n}. {code(entry.get('id'))} in {code(entry.get('package'))}**", ""]
        fix = FIX_LINE
    else:
        where = _label(entry.get("file"), entry.get("line"))
        out = [f"**{n}. {code(entry.get('rule_id'))} at {code(where)}**", ""]
        fix = CODE_FIX_LINE
    reason = detail(entry, "reason", DETAIL)
    if reason:
        out.append(f"- Analysis: {reason}")
    out.append(f"- Recommended fix: {fix}")
    return out + [""]


def _suppressed_row(entry, kind, repo, head):
    sup = entry.get("suppression") if isinstance(entry.get("suppression"), dict) else {}
    p = _parts(entry, kind, repo, head)
    return [p["ident"], p["location"], text(sup.get("reason")), code(sup.get("expires"))]


def _known(data):
    value = data.get("verdict") if isinstance(data, dict) else None
    return value if isinstance(value, str) and value in VERDICTS else None


def final_verdict(summary, baseline, review_result):
    """The result of the whole gate and the mode that gave it.

    "ai": the AI summary holds a known verdict. "baseline": no usable AI summary, the
    review was skipped by design, and the baseline summary holds a known verdict.
    "incomplete": every other case, which is ERROR. review_result is untrusted."""
    if _known(summary):
        return summary["verdict"], "ai"
    if review_result == "skipped" and _known(baseline):
        return baseline["verdict"], "baseline"
    return "ERROR", "incomplete"


def render(summary, repo=None, run_url=None, baseline=None, review_result=None):
    summary = summary if isinstance(summary, dict) else None
    baseline = baseline if isinstance(baseline, dict) else None
    repo = repo if isinstance(repo, str) and REPO_RE.match(repo) else None
    run_url = run_url if isinstance(run_url, str) and RUN_URL_RE.match(run_url) else None

    verdict, mode = final_verdict(summary, baseline, review_result)
    ai = summary if mode == "ai" else None
    meta = ai or baseline or {}
    # With an AI error, the open scanner findings come from the baseline summary.
    src = ai if ai is not None and (verdict != "ERROR" or baseline is None) else (baseline or {})
    reviewed = ai is not None and verdict != "ERROR"

    head_raw = meta.get("head")
    head = head_raw if isinstance(head_raw, str) and SHA_RE.match(head_raw) else None
    base_raw = meta.get("base")
    base = base_raw if isinstance(base_raw, str) and SHA_RE.match(base_raw) else None

    findings = _dicts((ai or {}).get("findings"))
    deps = _dicts(src.get("triage"))
    codes = _dicts(src.get("scan"))
    limits = {}
    for source in (baseline, ai):
        if source is not None and isinstance(source.get("limits"), dict):
            limits.update(source["limits"])
    totals = (ai or {}).get("totals") if isinstance((ai or {}).get("totals"), dict) else {}

    def pick(items, *rulings):
        return [x for x in items if x.get("ruling") in rulings]

    f_block, f_sup, f_note = (pick(findings, r) for r in ("blocking", "suppressed", "note"))
    t_block, t_sup = pick(deps, "blocking"), pick(deps, "suppressed")
    c_block, c_sup, c_clr = (pick(codes, r) for r in ("blocking", "suppressed", "cleared"))
    # Older AI summaries gave a cleared dependency finding the ruling "note".
    t_clr = pick(deps, "cleared", "note")
    n_block = len(f_block) + len(t_block) + len(c_block)

    details = (ai or {}).get("details") is True
    heading = {"PASS": "Passed", "BLOCK": "Blocked", "ERROR": "Review incomplete"}[verdict]
    blocking_sentence = (f"**{n_block} blocking finding(s).** Resolve each one. To accept a risk "
                         "instead, the repository owner adds a suppression with a reason and an "
                         "expiry date to the gate's config file on the base branch.")
    out = [MARKER, "", f"## AI Security Gate: {heading}", ""]
    if mode == "baseline":
        out.append("The AI review did not run for this change. This result comes from the "
                   "deterministic scanners alone.")
        if verdict == "BLOCK":
            out += ["", blocking_sentence]
        elif verdict == "ERROR":
            out += ["", f"**The scanner baseline did not finish:** {text(baseline.get('error'))}. "
                    "The gate fails closed, so this change is blocked until a baseline completes."]
    elif mode == "incomplete":
        out.append("**The AI review did not finish.** The gate fails closed, so this change is "
                   "blocked until a review completes.")
    elif verdict == "PASS":
        out.append("No finding blocks this change.")
    elif verdict == "BLOCK":
        out.append(blocking_sentence)
    else:
        out.append(f"**The review did not finish:** {text(ai.get('error'))}. "
                   "The gate fails closed, so this change is blocked until a review completes.")
        if ai.get("error_request_id"):
            out += ["", f"Request ID of the failed call: {code(ai.get('error_request_id'))}"]
    out.append("")

    changed = (ai or {}).get("changed_files")
    parts = [f"Model: {code(ai.get('model_requested'))}"] if ai else []
    if base and head:
        parts.append(f"{code(base[:7])}..{code(head[:7])}")
    if isinstance(changed, list):
        parts.append(f"{len(changed)} changed file(s)")
    if run_url:
        parts.append(f"[run]({run_url})")
    if parts:
        out += [" | ".join(parts), ""]

    if ai:
        out += [f"Change findings: {len(f_block)} blocking, {len(f_sup)} accepted, "
                f"{len(f_note)} notes.", ""]
    middle = f"{len(t_clr) + len(c_clr)} cleared by the AI review" if reviewed \
        else "none reviewed by the AI"
    out += [f"Deterministic scan: {len(deps) + len(codes)} finding(s) of "
            f"{enum(limits.get('triage_min_severity'), SEVERITIES)} severity or higher; "
            f"{len(t_sup) + len(c_sup)} accepted by the owner, {middle}, "
            f"{len(t_block) + len(c_block)} blocking.", ""]

    warnings = []
    if meta.get("notice"):
        warnings.append("Warning: the base commit holds no gate config. The gate used the "
                        "limits of this change and ignored its suppressions.")
    returned, requested = (ai or {}).get("model_returned"), (ai or {}).get("model_requested")
    if returned is not None and returned != requested:
        warnings.append("Warning: the model that answered differs from the model requested.")
    for s in _dicts(meta.get("expired_suppressions")):
        which = s.get("id") or s.get("path")
        warnings.append(f"Warning: a suppression has expired and no longer applies: "
                        f"{code(which)}, expired on {code(s.get('expires'))}.")
    for w in warnings:
        out += [w, ""]

    entries = ([(f, "change") for f in f_block] + [(t, "dep") for t in t_block]
               + [(c, "code") for c in c_block])
    if entries:
        out += ["### Blocking findings", ""]
        rows = [_blocking_row(i, e, k, repo, head) for i, (e, k) in enumerate(entries, 1)]
        out += table(["#", "Source", "Severity", "CWE or ID", "Package", "AI verdict",
                      "Confidence", "Location"], rows)
        out.append("")
        keys = {"change": ("title", "impact", "fix"), "dep": ("reason",), "code": ("reason",)}
        if any(detail(e, key, 1) for e, k in entries for key in keys[k]):
            for i, (e, k) in enumerate(entries[:MAX_BLOCKS], 1):
                out += _block(i, e, k)
            if len(entries) > MAX_BLOCKS:
                out += [f"Details of {len(entries) - MAX_BLOCKS} more findings are in the "
                        "summary artifact.", ""]

    if f_sup or t_sup or c_sup:
        out += ["### Accepted risks", ""]
        rows = ([_suppressed_row(f, "change", repo, head) for f in f_sup]
                + [_suppressed_row(t, "dep", repo, head) for t in t_sup]
                + [_suppressed_row(c, "code", repo, head) for c in c_sup])
        out += table(["CWE or ID", "Location", "Justification", "Expires"], rows)
        out.append("")

    cleared = [(t, "dep") for t in t_clr] + [(c, "code") for c in c_clr]
    if cleared:
        out += [f"<details><summary>Cleared by AI review ({len(cleared)})</summary>", ""]
        rows = [_cleared_row(e, k, repo, head) for e, k in cleared]
        headers = ["Source", "CWE or ID", "Package", "Severity", "AI verdict", "Confidence",
                   "Location"]
        if details:
            rows = [row + [detail(e, "reason", LONG) or "-"]
                    for row, (e, _) in zip(rows, cleared)]
            headers.append("Analysis")
        out += table(headers, rows)
        out += ["", "</details>", ""]

    out += [f"<details><summary>Non-blocking findings ({len(f_note)})</summary>", ""]
    rule = ""
    if ai:
        rule = (f"A change finding blocks only when its severity is "
                f"{enum(limits.get('fail_on'), SEVERITIES)} or higher, its confidence is "
                f"{enum(limits.get('min_confidence'), CONFIDENCES)} or higher, "
                "and its file is in the change. ")
    out.append(
        rule + "A scanner finding of "
        f"{enum(limits.get('triage_min_severity'), SEVERITIES)} severity or higher blocks unless "
        "the AI review clears it with high confidence (not_reachable for a dependency finding, "
        "false_positive for a code finding) or the owner accepts it.")
    out.append("")
    if f_note:
        rows = [_row(f, repo, head) for f in f_note]
        headers = ["Kind", "CWE or ID", "Package", "Verdict", "Severity", "Confidence",
                   "Location"]
        if details:
            rows = [row + [detail(f, "title", SHORT) or "-"] for row, f in zip(rows, f_note)]
            headers.append("Details")
        out += table(headers, rows)
        out.append("")
    out += ["</details>", ""]

    run = []
    if ai:
        run += [f"- Final stop reason: {code(ai.get('final_stop_reason'))}",
                f"- Model requested: {code(requested)}",
                f"- Model returned: {code(returned)}",
                f"- Effort: {enum(limits.get('effort'), ('low', 'medium', 'high', 'xhigh', 'max'))}"]
        run += [f"- {code(key)}: {num(totals[key])}"
                for key in sorted(k for k in totals if isinstance(k, str))]
    scanners = _dicts((ai or {}).get("scanners")) or _dicts((baseline or {}).get("scanners"))
    if scanners:
        run.append("- Scanners: " + ", ".join(
            code(f"{s.get('name') or ''} {s.get('version') or ''}".strip()) for s in scanners))
    if run:
        out += ["<details><summary>Run details</summary>", ""] + run + ["", "</details>", ""]

    if details:
        out.append(f"Finding descriptions are AI-generated by {code(requested)}. "
                   "Check each one against the code before you act on it.")
    else:
        out.append("This report shows severity, weakness class, and location. "
                   "Finding descriptions are not published for this repository.")

    result = "\n".join(out) + "\n"
    if len(result) > MAX_REPORT:
        tail = "\n\nThe report was cut at 60000 characters; see the summary artifact.\n"
        result = result[:MAX_REPORT - len(tail)].rsplit("\n", 1)[0] + tail
    return result


def _load(path, label):
    """The JSON object in path, or None with one line on standard error."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError) as e:
        print(f"report.py: cannot read {label}: {type(e).__name__}", file=sys.stderr)
        return None
    if not isinstance(data, dict):
        print(f"report.py: {label} is not a JSON object", file=sys.stderr)
        return None
    return data


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("summary_path", nargs="?", metavar="summary",
                    help="alias of --summary")
    ap.add_argument("--summary")
    ap.add_argument("--baseline")
    ap.add_argument("--review-result")
    ap.add_argument("--verdict-out")
    ap.add_argument("--repo")
    ap.add_argument("--run-url")
    args = ap.parse_args(argv)
    summary = _load(args.summary or args.summary_path, "summary")
    baseline = _load(args.baseline, "baseline summary")
    verdict, mode = final_verdict(summary, baseline, args.review_result)
    if summary is not None and mode != "ai":
        print("report.py: summary holds no known verdict", file=sys.stderr)
    sys.stdout.write(render(summary, args.repo, args.run_url, baseline, args.review_result))
    sys.stdout.flush()
    if args.verdict_out:
        try:
            with open(args.verdict_out, "w", encoding="utf-8") as fh:
                fh.write(verdict + "\n")
        except OSError as e:
            print(f"report.py: cannot write verdict file: {type(e).__name__}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
