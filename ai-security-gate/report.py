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
import os
import re
import sys
import unicodedata
from urllib.parse import quote

MARKER = "<!-- ai-security-gate-report -->"
SCAN_MARKER = "<!-- security-scan-report -->"
OPEN_FOLD = 10
MAX_REPORT = 60000
MAX_ROWS = 50
SHORT = 200
LONG = 300
DETAIL = 500
MAX_BLOCKS = 20
PROOF_RESULTS_NAME = "ai-security-gate-proof-results.json"
PROOF_RESULTS = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "error": "error"}
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
    if len(value) > limit:
        value = value[:limit - 3] + "..."
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


def _int(value):
    return type(value) is int


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


def _dep_finding(entry):
    """Advisory link, the installed package, and the fixed version."""
    ident = id_cell(entry.get("id"))
    pkg = entry.get("package")
    if not isinstance(pkg, str) or not pkg:
        return ident
    installed = entry.get("installed_version")
    name = f"{pkg} {installed}" if isinstance(installed, str) and installed else pkg
    fixed = entry.get("fixed_version")
    tail = f"fixed in {code(fixed)}" if isinstance(fixed, str) and fixed \
        else "no fixed version listed"
    return f"{ident} in {code(name)}, {tail}"


def _parts(entry, kind, repo, head, dep_name=None):
    """The cells that the blocking and cleared tables share: what the tool flagged
    (flagged, ident, severity, location), then what the AI says (verdict).
    kind is "change", "dep" (dependency finding), or "code" (code scan finding)."""
    if kind == "change":
        return {"flagged": "AI review", "ident": id_cell(entry.get("cwe")),
                "severity": enum(entry.get("severity"), SEVERITIES), "verdict": "-",
                "location": location_cell(entry.get("file"), entry.get("line"), repo, head)}
    verdict = entry.get("verdict")
    if kind == "dep":
        if verdict is None:
            shown = NOT_REVIEWED
        else:
            shown = enum(verdict, TRIAGE_VERDICTS)
            if verdict == "reachable" and entry.get("file"):
                shown += " at " + location_cell(entry.get("file"), entry.get("line"), repo, head)
        return {"flagged": code(dep_name) if dep_name is not None else "Dependency scan",
                "ident": _dep_finding(entry), "severity": _sev(entry), "verdict": shown,
                "location": location_cell(entry.get("target"), None, repo, head)}
    return {"flagged": code(entry.get("tool")), "ident": id_cell(entry.get("rule_id")),
            "severity": _sev(entry),
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


def _blocking_row(n, entry, kind, repo, head, dep_name=None):
    p = _parts(entry, kind, repo, head, dep_name)
    return [str(n), p["flagged"], p["ident"], p["severity"], p["location"], p["verdict"],
            _conf(entry)]


def _cleared_row(entry, kind, repo, head, dep_name=None):
    p = _parts(entry, kind, repo, head, dep_name)
    return [p["flagged"], p["ident"], p["severity"], p["location"], p["verdict"], _conf(entry)]


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
    out.append(f"- AI analysis: {reason}" if reason else f"- Recommended fix: {fix}")
    return out + [""]


def _sup_key(entry):
    """The (path, id, cwe, reason, expires) of an entry's suppression; None for a
    missing or non-string value."""
    sup = entry.get("suppression") if isinstance(entry.get("suppression"), dict) else {}
    return tuple(v if isinstance(v := sup.get(k), str) else None
                 for k in ("path", "id", "cwe", "reason", "expires"))


def _accepted_row(key, count):
    path, ident, cwe, reason, expires = key
    cell = ", ".join(
        ([f"path {code(path)}"] if path else []) + ([f"ID {id_cell(ident)}"] if ident else [])
        + ([f"CWE {id_cell(cwe)}"] if cwe else [])) or "-"
    return [cell, text(reason), code(expires), str(count)]


def _scanner_rows(scanners, deps, codes):
    """One row per scanner: findings, accepted by the owner, open."""
    def row(label, entries):
        ruled = [e.get("ruling") for e in entries]
        return [label, str(len(entries)), str(ruled.count("suppressed")),
                str(ruled.count("blocking"))]

    def label(s):
        return code(f"{s.get('name') or ''} {s.get('version') or ''}".strip())

    def tool(value):
        return value if isinstance(value, str) else ""

    rows = []
    dep_scanners = [s for s in scanners if s.get("kind") == "dependency"]
    if dep_scanners or deps:
        name = "Dependency scan" + (f" {label(dep_scanners[0])}" if dep_scanners else "")
        rows.append(row(name, deps))
    versions = {}
    for s in scanners:
        if s.get("kind") in (None, "code"):
            versions.setdefault(tool(s.get("name")), s)
    for e in codes:
        versions.setdefault(tool(e.get("tool")), None)
    for name, s in versions.items():
        text_label = label(s) if s else code(name)
        rows.append(row(f"Code scan {text_label}",
                        [e for e in codes if tool(e.get("tool")) == name]))
    return rows


def _known(data):
    value = data.get("verdict") if isinstance(data, dict) else None
    return value if isinstance(value, str) and value in VERDICTS else None


def _category(request):
    cat = request.get("stop_category")
    return cat if isinstance(cat, str) and cat else None


def _proof_refused(summary):
    proof = summary.get("proof")
    return isinstance(proof, dict) and proof.get("stage") == "refused"


def refusal(summary):
    """(True, category or None) when the summary records a model refusal, else None.
    Reads only verdict, final_stop_reason, the last request's stop fields, and, for a
    refusal at the proof stage, the proof stage and its last request."""
    if not isinstance(summary, dict) or summary.get("verdict") != "ERROR":
        return None
    reqs = _dicts(summary.get("requests"))
    last = reqs[-1] if reqs else {}
    if summary.get("final_stop_reason") != "refusal" and last.get("stop_reason") != "refusal":
        if not _proof_refused(summary):
            return None
        proof_reqs = _dicts(summary["proof"].get("requests"))
        return True, _category(proof_reqs[-1] if proof_reqs else {})
    return True, _category(last)


def proof_refusal(summary):
    """The first proof entry's ID or CWE (a string, or "" when unknown) when the refusal
    is a refusal at the proof stage; None for a refusal of the review itself."""
    if not refusal(summary):
        return None
    reqs = _dicts(summary.get("requests"))
    last = reqs[-1] if reqs else {}
    if summary.get("final_stop_reason") == "refusal" or last.get("stop_reason") == "refusal":
        return None
    for key, field in (("findings", "cwe"), ("triage", "id"), ("scan", "rule_id")):
        for e in _dicts(summary.get(key)):
            if _int(e.get("proof")) and e["proof"] == 1:
                value = e.get(field)
                return value if isinstance(value, str) else ""
    return ""


def refusing_model(summary):
    """The model that answered, else the model requested."""
    returned = summary.get("model_returned")
    return returned if isinstance(returned, str) and returned else summary.get("model_requested")


def refusal_line(model, category, proof_ident=None):
    """proof_ident is None for a refusal of the review, else the ID or CWE of proof 1."""
    where = f", category: {code(category)}" if category else ""
    closing = ("The gate does not switch to another model. To get a review from "
               "another model, start a new run and write that model's ID in the approval "
               "comment.")
    if proof_ident is None:
        return (f"**{code(model)} refused to run this security review** (stop reason: refusal"
                f"{where}). {closing}")
    what = code(proof_ident) if proof_ident else "this finding"
    return (f"**{code(model)} refused to write a proof test for this review** (stop reason: "
            f"refusal{where}). The triage finished. The model declined the request for a "
            f"read-only test that confirms or refutes {what} on the running app. {closing}")


def _refusal_of(summary):
    """(model, category, proof_ident) of a summary that holds a refusal."""
    return refusing_model(summary), refusal(summary)[1], proof_refusal(summary)


def proof_cells(summary, results):
    """({n: entry outcome}, written, confirmed, not confirmed, error) of the proof stage;
    an empty dict when it holds no entry. results maps n to a run outcome."""
    proof = summary.get("proof") if isinstance(summary, dict) else None
    entries = {}
    if isinstance(proof, dict):
        for e in _dicts(proof.get("entries")):
            if _int(e.get("n")) and isinstance(e.get("outcome"), str):
                entries.setdefault(e["n"], e["outcome"])
    written = [n for n, o in entries.items() if o == "written"]
    got = [results.get(n) for n in written]
    return (entries, len(written), got.count("confirmed"), got.count("not_confirmed"),
            got.count("error"))


def _proof_cell(entry, entries, results):
    n = entry.get("proof")
    if not _int(n) or n not in entries:
        return "-"
    outcome = entries[n]
    if outcome == "invalid":
        return "no valid test"
    if outcome == "written":
        return PROOF_RESULTS.get(results.get(n), "not run")
    return "error" if outcome == "error" else "-"


def clean_results(data):
    """{n: outcome} from an untrusted proof results object. Only an integer n with the
    outcome confirmed, not_confirmed, or error stays; the first entry for an n wins."""
    out = {}
    for e in _dicts(data.get("results") if isinstance(data, dict) else None):
        n, outcome = e.get("n"), e.get("outcome")
        if _int(n) and isinstance(outcome, str) and outcome in PROOF_RESULTS:
            out.setdefault(n, outcome)
    return out


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


def pick_summary(summaries):
    """The one summary that stands for several review runs, and a forced-error flag.

    summaries holds the loaded objects in argument order; an unreadable file is None.
    BLOCK wins, then ERROR, then an entry that is None or holds no known verdict
    (forced error), then PASS. An empty list gives (None, False)."""
    for wanted in ("BLOCK", "ERROR"):
        for s in summaries:
            if _known(s) == wanted:
                return s, False
    if any(_known(s) is None for s in summaries):
        return None, True
    for s in summaries:
        if _known(s) == "PASS":
            return s, False
    return None, False


def _accepted_fold(entries):
    """The folded Accepted risks section, one row per suppression; empty with no entry."""
    if not entries:
        return []
    groups = {}
    for e in entries:
        key = _sup_key(e)
        groups[key] = groups.get(key, 0) + 1
    out = [f"<details><summary>Accepted risks ({len(entries)} "
           f"finding(s) under {len(groups)} suppression(s))</summary>", ""]
    out += table(["Suppression", "Justification", "Expires", "Findings"],
                 [_accepted_row(k, n) for k, n in groups.items()])
    return out + ["", "The summary artifact of this run lists each accepted finding.", "",
                  "</details>", ""]


def _warnings(meta, model_warning=None):
    """The notice line, an optional model line, and one line per expired suppression."""
    warnings = []
    if meta.get("notice"):
        warnings.append("Warning: the base commit holds no gate config. The gate used the "
                        "limits of this change and ignored its suppressions.")
    if model_warning:
        warnings.append(model_warning)
    for s in _dicts(meta.get("expired_suppressions")):
        which = s.get("id") or s.get("path")
        warnings.append(f"Warning: a suppression has expired and no longer applies: "
                        f"{code(which)}, expired on {code(s.get('expires'))}.")
    return warnings


def _cut(out):
    result = "\n".join(out) + "\n"
    if len(result) > MAX_REPORT:
        tail = "\n\nThe report was cut at 60000 characters; see the summary artifact.\n"
        result = result[:MAX_REPORT - len(tail)].rsplit("\n", 1)[0] + tail
    return result


def _sha(value):
    return value if isinstance(value, str) and SHA_RE.match(value) else None


def render_scan(baseline, repo=None, run_url=None):
    """The scan comment: scanner results only, no text written by the AI."""
    baseline = baseline if isinstance(baseline, dict) else None
    repo = repo if isinstance(repo, str) and REPO_RE.match(repo) else None
    run_url = run_url if isinstance(run_url, str) and RUN_URL_RE.match(run_url) else None
    meta = baseline or {}
    head, base = _sha(meta.get("head")), _sha(meta.get("base"))
    verdict = _known(baseline)
    done = verdict in ("PASS", "BLOCK")

    deps = _dicts(meta.get("triage"))
    codes = _dicts(meta.get("scan"))
    limits = meta.get("limits") if isinstance(meta.get("limits"), dict) else {}
    scanners = _dicts(meta.get("scanners"))
    dep_scanner = next((s for s in scanners if s.get("kind") == "dependency"), None)
    dep_name = f"{dep_scanner.get('name') or ''}" if dep_scanner else None
    open_deps = [e for e in deps if e.get("ruling") == "blocking"]
    open_codes = [e for e in codes if e.get("ruling") == "blocking"]
    n_open = len(open_deps) + len(open_codes)
    accepted = [e for e in deps + codes if e.get("ruling") == "suppressed"]

    if not done:
        heading = "did not finish"
    elif verdict == "BLOCK":
        heading = f"{n_open} open finding(s)"
    else:
        heading = "no open findings"
    out = [SCAN_MARKER, "", f"## Security scan: {heading}", ""]
    if not done:
        error = meta.get("error")
        what = (f"**The scan did not finish:** {text(error)}." if isinstance(error, str) and error
                else "**The scan did not finish.**")
        out.append(f"{what} The gate fails closed, so this change is blocked until a scan "
                   "completes.")
    elif n_open:
        out.append("Each open finding blocks this change unless the AI review clears it or the "
                   "repository owner accepts it.")
    else:
        out.append("No scanner finding is open.")
    out.append("")

    parts = [f"{code(base[:7])}..{code(head[:7])}"] if base and head else []
    if run_url:
        parts.append(f"[run]({run_url})")
    if parts:
        out += [" | ".join(parts), ""]
    named = code(head[:7]) if head else "this commit"
    out += ["The AI review posts its result in a separate comment when the review job ends. "
            f"Until that comment names {named}, this change has not passed the gate.", ""]

    if done:
        out += [f"{len(deps) + len(codes)} finding(s) of "
                f"{enum(limits.get('triage_min_severity'), SEVERITIES)} severity or higher: "
                f"{len(accepted)} accepted by the owner, {n_open} open.", ""]
        rows = _scanner_rows(scanners, deps, codes)
        if rows:
            out += table(["Scanner", "Findings", "Accepted by owner", "Open"], rows) + [""]
        for w in _warnings(meta):
            out += [w, ""]
        if n_open:
            rows = []
            for e, kind in [(e, "dep") for e in open_deps] + [(e, "code") for e in open_codes]:
                p = _parts(e, kind, repo, head, dep_name)
                rows.append([p["flagged"], p["ident"], p["severity"], p["location"]])
            shown = table(["Flagged by", "Finding", "Severity", "Location"], rows)
            if n_open > OPEN_FOLD:
                out += [f"<details><summary>Open findings ({n_open})</summary>", ""] + shown \
                    + ["", "</details>", ""]
            else:
                out += ["### Open findings", ""] + shown + [""]
        out += _accepted_fold(accepted)
        out.append("This comment holds scanner results only: the advisory or rule ID, severity, "
                   "and location. It holds no AI-written text.")
    return _cut(out)


def render(summary, repo=None, run_url=None, baseline=None, review_result=None, reviews=None,
           refusals=None, proof_results=None):
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

    head, base = _sha(meta.get("head")), _sha(meta.get("base"))

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
    picked_refusal = ai is not None and verdict == "ERROR" and refusal(ai)
    if picked_refusal:
        heading = "Review refused"
    if refusals is None:
        refusals = [_refusal_of(ai)] if picked_refusal else []
    blocking_sentence = (f"**{n_block} blocking finding(s).** Resolve each one. To accept a risk "
                         "instead, the repository owner adds a suppression with a reason and an "
                         "expiry date to the gate's config file on the base branch.")
    if mode == "baseline" and verdict in ("PASS", "BLOCK"):
        heading = "not run"
    out = [MARKER, "", f"## AI review: {heading}", ""]
    if picked_refusal:
        # The reader sees which model refused before anything else.
        for model, category, *proof in refusals:
            out += [refusal_line(model, category, *proof), ""]
        refusals = []
    if mode == "baseline":
        if verdict == "ERROR":
            out.append("The AI review did not run for this change. This result comes from the "
                       "deterministic scanners alone.")
            out += ["", f"**The scanner baseline did not finish:** {text(baseline.get('error'))}. "
                    "The gate fails closed, so this change is blocked until a baseline completes."]
        else:
            result_word = "passed" if verdict == "PASS" else "blocked"
            out.append("The AI review did not run for this change. The gate result comes from "
                       f"the deterministic scan alone: **{result_word}**.")
            if verdict == "BLOCK":
                out += ["", blocking_sentence]
    elif mode == "incomplete":
        out.append("**The AI review did not finish.** The gate fails closed, so this change is "
                   "blocked until a review completes.")
    elif verdict == "PASS":
        out.append("No finding blocks this change.")
        if review_result == "failure":
            out += ["", "The review job of this attempt failed. This result comes from an "
                    "earlier attempt of the same run."]
    elif verdict == "BLOCK":
        out.append(blocking_sentence)
    elif picked_refusal:
        out.append("The gate fails closed, so this change is blocked until a review completes.")
        if ai.get("error_request_id"):
            out += ["", f"Request ID of the failed call: {code(ai.get('error_request_id'))}"]
    else:
        out.append(f"**The review did not finish:** {text(ai.get('error'))}. "
                   "The gate fails closed, so this change is blocked until a review completes.")
        if ai.get("error_request_id"):
            out += ["", f"Request ID of the failed call: {code(ai.get('error_request_id'))}"]
    out.append("")
    for model, category, *proof in refusals:
        out += [refusal_line(model, category, *proof), ""]
    if isinstance(reviews, list) and len(reviews) > 1:
        line = "Reviews in this run: " + ", ".join(
            f"{code(model)} {enum(v, VERDICTS + ('REFUSED',))}" for model, v in reviews) + "."
        if ai:
            line += f" The report below is from {code(ai.get('model_requested'))}."
        out += [line, ""]

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
    scanners = _dicts((ai or {}).get("scanners")) or _dicts((baseline or {}).get("scanners"))
    dep_scanner = next((s for s in scanners if s.get("kind") == "dependency"), None)
    dep_name = f"{dep_scanner.get('name') or ''}" if dep_scanner else None
    n_cleared, n_open = len(t_clr) + len(c_clr), len(t_block) + len(c_block)
    if reviewed:
        out += [f"Scanner findings sent to the AI review: {n_cleared + n_open}; "
                f"{n_cleared} cleared, {n_open} blocking.", ""]
    elif n_open:
        out += [f"{n_open} open scanner finding(s) were not reviewed by the AI. "
                "The Security scan comment lists them.", ""]

    returned, requested = (ai or {}).get("model_returned"), (ai or {}).get("model_requested")
    differs = "Warning: the model that answered differs from the model requested." \
        if returned is not None and returned != requested else None
    for w in _warnings(meta, differs):
        out += [w, ""]

    entries = ([(f, "change") for f in f_block] + [(t, "dep") for t in t_block]
               + [(c, "code") for c in c_block])
    if entries and reviewed:
        out += ["### Blocking findings", ""]
        rows = [_blocking_row(i, e, k, repo, head, dep_name)
                for i, (e, k) in enumerate(entries, 1)]
        headers = ["#", "Flagged by", "Finding", "Severity", "Location", "AI verdict",
                   "Confidence"]
        results = {n: o for n, o in (proof_results or {}).items()
                   if _int(n) and isinstance(o, str) and o in PROOF_RESULTS}
        p_entries, p_written, p_ok, p_not, p_err = proof_cells(ai, results)
        if p_entries:
            out += [f"Proof tests: {num(p_written)} written by {code(requested)} and run against "
                    "the app in a container with no outside network: "
                    f"{num(p_ok)} confirmed, {num(p_not)} not confirmed, {num(p_err)} error. "
                    "A proof test passes only when it shows the flaw on the running app. A "
                    "finding blocks with or without one. The test code is not published.", ""]
            headers.append("Proof")
            rows = [row + [_proof_cell(e, p_entries, results)]
                    for row, (e, _) in zip(rows, entries)]
        out += table(headers, rows)
        out.append("")
        if any(k != "change" and e.get("verdict") in ("not_reachable", "false_positive")
               for e, k in entries):
            out += ["A scanner finding stays blocking unless the AI review clears it with high "
                    "confidence.", ""]
        keys = {"change": ("title", "impact", "fix"), "dep": ("reason",), "code": ("reason",)}
        if any(detail(e, key, 1) for e, k in entries for key in keys[k]):
            for i, (e, k) in enumerate(entries[:MAX_BLOCKS], 1):
                out += _block(i, e, k)
            if len(entries) > MAX_BLOCKS:
                out += [f"Details of {len(entries) - MAX_BLOCKS} more findings are in the "
                        "summary artifact.", ""]

    out += _accepted_fold(f_sup)

    cleared = [(t, "dep") for t in t_clr] + [(c, "code") for c in c_clr]
    if cleared:
        out += [f"<details><summary>Cleared by AI review ({len(cleared)})</summary>", ""]
        rows = [_cleared_row(e, k, repo, head, dep_name) for e, k in cleared]
        headers = ["Flagged by", "Finding", "Severity", "Location", "AI verdict", "Confidence"]
        if details:
            rows = [row + [detail(e, "reason", LONG) or "-"]
                    for row, (e, _) in zip(rows, cleared)]
            headers.append("AI analysis")
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
    if run:
        out += ["<details><summary>Run details</summary>", ""] + run + ["", "</details>", ""]

    if details:
        out.append(f"Finding descriptions are AI-generated by {code(requested)}. "
                   "Check each one against the code before you act on it.")
    else:
        out.append("This report shows severity, weakness class, and location. "
                   "Finding descriptions are not published for this repository.")

    return _cut(out)


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


def _load_proof_results(summary_path):
    """The cleaned results file beside a summary file; {} when it does not exist."""
    path = os.path.join(os.path.dirname(summary_path), PROOF_RESULTS_NAME)
    if not os.path.exists(path):
        return {}
    return clean_results(_load(path, "proof results"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("summary_path", nargs="?", metavar="summary",
                    help="alias of --summary")
    ap.add_argument("--summary", action="append", default=[],
                    help="a review summary; repeat it for several reviews")
    ap.add_argument("--baseline")
    ap.add_argument("--review-result")
    ap.add_argument("--verdict-out")
    ap.add_argument("--repo")
    ap.add_argument("--run-url")
    ap.add_argument("--part", choices=("scan", "review"), default="review")
    args = ap.parse_args(argv)
    if args.part == "scan":
        sys.stdout.write(render_scan(_load(args.baseline, "baseline summary"), args.repo,
                                     args.run_url))
        sys.stdout.flush()
        return 0
    paths = args.summary + ([args.summary_path] if args.summary_path else [])
    loaded = [_load(path, "summary") for path in paths]
    baseline = _load(args.baseline, "baseline summary")
    summary, forced_error = pick_summary(loaded)
    review_result = None if forced_error else args.review_result
    verdict, mode = final_verdict(summary, baseline, review_result)
    for s in loaded:
        if s is not None and _known(s) is None:
            print("report.py: summary holds no known verdict", file=sys.stderr)
    reviews = [(refusing_model(s) if refusal(s) else s.get("model_requested"),
                "REFUSED" if refusal(s) else s["verdict"])
               for s in loaded if _known(s)]
    refusals = [_refusal_of(s) for s in loaded if refusal(s)]
    proof_results = {}
    for path, s in zip(paths, loaded):
        if s is summary and summary is not None:
            proof_results = _load_proof_results(path)
            break
    sys.stdout.write(render(summary, args.repo, args.run_url, baseline, review_result, reviews,
                            refusals, proof_results))
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
