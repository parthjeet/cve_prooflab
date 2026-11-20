import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import report  # noqa: E402

HERE = Path(__file__).resolve().parent
REPORT_PY = HERE.parent / "report.py"
FIXTURES = HERE / "fixtures" / "report"
FIXTURE = FIXTURES / "pass-summary.json"
AI_BLOCK = FIXTURES / "ai-block-summary.json"
BASELINE_BLOCK = FIXTURES / "baseline-block.json"
BASELINE_PASS = FIXTURES / "baseline-pass.json"
BLOCKING_HEADER = "| # | Flagged by | Finding | Severity | Location | AI verdict | Confidence |"
CLEARED_HEADER = "| Flagged by | Finding | Severity | Location | AI verdict | Confidence |"
HEAD = "d55cf8d58f3af4939216e95aa0f6a56c01113d7d"
BASE = "830e3b425107e8f9f797c876b41d94273d2f8758"


def real():
    return json.loads(FIXTURE.read_text())


def base_summary(**kw):
    s = {"model_requested": "m-1", "model_returned": "m-1", "final_stop_reason": "end_turn",
         "base": BASE, "head": HEAD, "changed_files": ["a.py"],
         "limits": {"fail_on": "high", "min_confidence": "medium", "effort": "medium",
                    "triage_min_severity": "medium"},
         "notice": None, "requests": [], "tool_calls": [], "totals": {"requests": 1},
         "findings": [], "triage": [], "expired_suppressions": [],
         "verdict": "PASS", "error": None, "error_request_id": None}
    s.update(kw)
    return s


def change(**kw):
    f = {"severity": "high", "confidence": "high", "cwe": "CWE-22", "file": "a.py", "line": 3,
         "ruling": "blocking", "suppression": None}
    f.update(kw)
    return f


def scan(**kw):
    t = {"id": "CVE-2025-12345", "package": "pkgtool", "verdict": "reachable",
         "confidence": "high", "file": "a.py", "line": 5, "ruling": "blocking",
         "suppression": None}
    t.update(kw)
    return t


def code_entry(**kw):
    c = {"key": "S1", "tool": "example-sast", "rule_id": "python.sql.formatted-query",
         "severity": "high", "file": "db.py", "line": 12, "verdict": "true_positive",
         "confidence": "high", "ruling": "blocking", "suppression": None}
    c.update(kw)
    return c


def load(path):
    return json.loads(path.read_text())


def test_real_pass_summary():
    out = report.render(real(), "o/r", None)
    assert "## AI review: Passed" in out
    assert "### Blocking findings" not in out
    assert "### Accepted risks" not in out
    # the accepted scanner finding of the fixture shows in the scan comment, not here
    assert "Accepted risks" not in out and "CVE-2026-48817" not in out
    assert "Scanner findings sent to the AI review: 10; 10 cleared, 0 blocking." in out
    # the fixture predates the ruling "cleared"; its ten "note" entries read as cleared
    assert "Cleared by AI review (10)" in out and "Non-blocking findings (0)" in out
    assert "| Details |" not in out and "AI analysis" not in out
    assert "Finding descriptions are not published for this repository." in out
    for word in ("Deliberate", "on purpose", "Suppressed"):
        assert word not in out
    assert "45105" in out and "2867" in out


def test_block_order():
    s = base_summary(verdict="BLOCK", findings=[change()], triage=[scan(id="CVE-2025-99999")])
    s["findings"].append(change(ruling="suppressed", file="b.py",
                                suppression={"reason": "r", "expires": "2027-01-01"}))
    out = report.render(s, "o/r")
    b, sp, d = (out.index("### Blocking findings"), out.index("<details><summary>Accepted risks"),
                out.index("<details><summary>Non-blocking"))
    assert b < sp < d
    blocking = out[b:sp]
    assert "CWE-22" in blocking and "CVE-2025-99999" in blocking
    assert BLOCKING_HEADER in blocking
    assert "AI review" in blocking and "Dependency scan" in blocking
    assert "## AI review: Blocked" in out
    assert "**2 blocking finding(s).** Resolve each one." in out


def test_error():
    s = base_summary(verdict="ERROR", error="boom happened", error_request_id="req_abc123")
    out = report.render(s)
    assert "## AI review: Review incomplete" in out
    assert "**The review did not finish:** boom happened. The gate fails closed, so this " \
        "change is blocked until a review completes." in out
    assert "req_abc123" in out
    assert "| Kind" not in out and "### " not in out
    assert "req_abc123" not in report.render(base_summary(error_request_id="req_abc123"))


def test_hostile_strings():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    s = base_summary(
        verdict="ERROR", error=evil + big, error_request_id=evil,
        findings=[change(file=evil + big, ruling="suppressed",
                         suppression={"reason": evil + big, "expires": evil})],
        triage=[scan(id=evil + big, package=evil + big, file=evil, ruling="blocking")])
    out = report.render(s, "o/r")
    assert "<script" not in out
    assert "`" not in out
    assert "@someone" not in out and "(at)" not in out.replace("&#40;at&#41;", "")
    assert not any(ln.startswith("::") for ln in out.splitlines())
    assert "](http://x)" not in out
    assert "Z" * 301 not in out
    # values in <code> are cut at 200 characters, the error and reason at 300
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200
    assert "Z" * 250 in out


def test_row_cap_and_size():
    s = base_summary(triage=[scan(id=f"CVE-2025-{1000 + i}", verdict="not_reachable",
                                  ruling="cleared") for i in range(80)])
    out = report.render(s)
    notes = out.split("Cleared by AI review (80)")[1].split("</details>")[0]
    assert sum(1 for ln in notes.splitlines() if ln.startswith("| ") and "CVE-" in ln) == 50
    assert "and 30 more; see the summary artifact" in out
    huge = base_summary(findings=[change(ruling="blocking", file="f" * 150 + str(i))
                                  for i in range(1000)],
                        triage=[scan(ruling="cleared", id="X" * 190 + str(i)) for i in range(1000)],
                        verdict="BLOCK")
    assert len(report.render(huge, "o/r")) <= 60000
    giant = base_summary(totals={f"k{i}": i for i in range(20000)})
    out = report.render(giant)
    assert len(out) <= 60000 and "cut at 60000" in out


def test_warnings():
    out = report.render(base_summary())
    assert "no gate config" not in out and "differs" not in out
    assert ("Warning: the base commit holds no gate config. The gate used the limits of this "
            "change and ignored its suppressions.") in report.render(base_summary(notice="x"))
    assert "differs from the model requested" in report.render(base_summary(model_returned="m-2"))
    out = report.render(base_summary(expired_suppressions=[
        {"path": None, "id": "CVE-2025-1111", "cwe": None, "reason": "r",
         "expires": "2026-01-01"}]))
    assert "has expired" in out and "CVE-2025-1111" in out and "2026-01-01" in out


def test_leaves_out_tool_paths_and_request_ids():
    s = base_summary(
        tool_calls=[{"name": "read_file", "path": "SENTINEL-PATH-77"}],
        requests=[{"request_id": "SENTINEL-REQ-88", "stop_reason": "end_turn",
                   "stop_category": None, "usage": {}}])
    out = report.render(s)
    assert "SENTINEL" not in out


def run_cli(*args):
    return subprocess.run([sys.executable, str(REPORT_PY), *args], capture_output=True, text=True)


def test_cli_absent_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    lst = tmp_path / "list.json"
    lst.write_text("[1]")
    noverdict = tmp_path / "nv.json"
    noverdict.write_text("{}")
    for p in (tmp_path / "missing.json", bad, lst, noverdict):
        r = run_cli(str(p))
        assert r.returncode == 0 and "## AI review: Review incomplete" in r.stdout
        assert "**The AI review did not finish.**" in r.stdout
        assert len(r.stderr.strip().splitlines()) == 1
    r = run_cli()
    assert r.returncode == 0 and r.stderr == "" and "Review incomplete" in r.stdout


def test_marker_and_links():
    out = report.render(real())
    assert out.splitlines()[0] == "<!-- ai-security-gate-report -->"
    out = report.render(base_summary(findings=[change()]), "o/r",
                        "https://github.com/o/r/actions/runs/5")
    assert f"https://github.com/o/r/blob/{HEAD}/a.py#L3" in out
    assert "https://cwe.mitre.org/data/definitions/22.html" in out
    assert "[run](https://github.com/o/r/actions/runs/5)" in out
    out = report.render(base_summary(findings=[change()]), "bad repo", "https://evil.example/x")
    assert "blob/" not in out and "evil.example" not in out and "[run]" not in out
    ok = run_cli(str(FIXTURE), "--repo", "o/r")
    assert ok.returncode == 0 and ok.stdout.splitlines()[0] == report.MARKER


def detailed(**kw):
    s = base_summary(verdict="BLOCK", details=True, **kw)
    return s


def with_text(entry, **kw):
    return {**entry, **kw}


def test_block_with_details():
    f = with_text(change(), title="Query built from input", impact="Reads any row.",
                  fix="Use a parameterized query.")
    t = with_text(scan(), reason="The route calls the affected function.")
    n = with_text(change(ruling="note", severity="low"), title="Minor note title")
    nt = with_text(scan(id="CVE-2025-1", ruling="cleared", verdict="not_reachable"),
                   reason="Never imported.")
    out = report.render(detailed(findings=[f, n], triage=[t, nt]), "o/r")
    assert out.index("### Blocking findings") < out.index("<details>")
    assert "**1. Query built from input**" in out
    assert "- Impact: Reads any row." in out
    assert "- Recommended fix: Use a parameterized query." in out
    assert "**2. <code>CVE-2025-12345</code> in <code>pkgtool</code>**" in out
    assert "- AI analysis: The route calls the affected function." in out
    assert "- Analysis:" not in out
    assert report.FIX_LINE not in out
    notes = out.split("Non-blocking findings (1)")[1].split("</details>")[0]
    assert "| Details |" in notes and "Minor note title" in notes
    cleared = out.split("Cleared by AI review (1)")[1].split("</details>")[0]
    assert "| AI analysis |" in cleared and "Never imported." in cleared
    assert "Finding descriptions are AI-generated by <code>m-1</code>. Check each one " \
        "against the code before you act on it." in out
    assert "not published" not in out


def test_block_without_details():
    out = report.render(base_summary(verdict="BLOCK", findings=[change()], triage=[scan()]))
    assert "### Blocking findings" in out and "**1. " not in out
    assert "Recommended fix" not in out and "not published" in out


def test_hostile_detail_strings():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    f = with_text(change(), title=evil + big, impact=evil + big, fix=evil + big)
    t = with_text(scan(), reason=evil + big)
    n = with_text(change(ruling="note"), title=evil + big)
    nt = with_text(scan(ruling="cleared", verdict="unknown"), reason=evil + big)
    out = report.render(detailed(findings=[f, n], triage=[t, nt]), "o/r")
    assert "<script" not in out and "`" not in out
    assert "@someone" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    assert "](http://x)" not in out
    # each field is cut at its limit, counted with the 45-character prefix of `evil`
    pre = len(evil)
    zs = {len(m) for m in re.findall(r"Z+", out)}
    assert zs == {197 - pre, 497 - pre, 297 - pre}
    title = [ln for ln in out.splitlines() if ln.startswith("**1. ")][0]
    assert title.count("Z") == 197 - pre
    impact = [ln for ln in out.splitlines() if ln.startswith("- Impact: ")][0]
    assert impact.count("Z") == 497 - pre


def test_non_string_detail_fields_are_skipped():
    f = with_text(change(), title=5, impact=["x"], fix="")
    out = report.render(detailed(findings=[f]), "o/r")
    assert "Impact:" not in out and "Recommended fix:" not in out


def test_evidence_and_answer_summary_never_appear():
    f = with_text(change(), evidence="SENTINEL-EVIDENCE", title="T1")
    s = detailed(findings=[f], summary="SENTINEL-SUMMARY", error_detail="SENTINEL-ERR")
    s["triage"] = [with_text(scan(), evidence="SENTINEL-EVIDENCE")]
    out = report.render(s)
    assert "SENTINEL" not in out


def test_detail_blocks_cap_at_20():
    fs = [with_text(change(file=f"a{i}.py"), title=f"Title {i}", impact="i", fix="f")
          for i in range(30)]
    out = report.render(detailed(findings=fs), "o/r")
    assert len(re.findall(r"^\*\*\d+\. ", out, re.M)) == 20
    assert "**20. Title 19**" in out and "**21. " not in out
    assert "Details of 10 more findings are in the summary artifact." in out


def test_final_verdict_table():
    ai = {"verdict": "BLOCK"}
    base = {"verdict": "PASS"}
    assert report.final_verdict(ai, base, "success") == ("BLOCK", "ai")
    assert report.final_verdict({"verdict": "ERROR"}, base, "skipped") == ("ERROR", "ai")
    assert report.final_verdict(None, base, "skipped") == ("PASS", "baseline")
    assert report.final_verdict(None, {"verdict": "BLOCK"}, "skipped") == ("BLOCK", "baseline")
    assert report.final_verdict(None, {"verdict": "ERROR"}, "skipped") == ("ERROR", "baseline")
    for result in ("success", "failure", "cancelled", None, "weird", 7, ["skipped"]):
        assert report.final_verdict(None, base, result) == ("ERROR", "incomplete")
    assert report.final_verdict(None, None, "skipped") == ("ERROR", "incomplete")
    assert report.final_verdict(None, {"verdict": "MAYBE"}, "skipped") == ("ERROR", "incomplete")
    # an AI summary with no known verdict counts as absent, as an unreadable file does
    for bad in ({}, {"verdict": "PASSED"}, {"verdict": ["PASS"]}, {"verdict": None}):
        assert report.final_verdict(bad, base, "success") == ("ERROR", "incomplete")
        assert report.final_verdict(bad, base, "skipped") == ("PASS", "baseline")


def test_ai_mode_with_scanner_rows():
    out = report.render(load(AI_BLOCK), "o/r", baseline=load(BASELINE_BLOCK), review_result="success")
    assert "## AI review: Blocked" in out
    assert "**2 blocking finding(s).** Resolve each one." in out
    assert "Change findings: 0 blocking, 0 accepted, 0 notes." in out
    assert "Scanner findings sent to the AI review: 4; 2 cleared, 2 blocking." in out
    block = out.split("### Blocking findings")[1].split("<details><summary>Cleared")[0]
    rows = [ln for ln in block.splitlines() if ln.startswith("| ") and "Flagged by" not in ln]
    assert len(rows) == 2
    dep, scan_row = rows
    assert "Dependency scan" in dep and "CVE-2025-12345" in dep and "reachable at" in dep
    assert "app/app.py&#58;23" in dep and "requirements.txt" in dep
    assert "<code>example-sast</code>" in scan_row
    assert "python.sql.formatted-query" in scan_row and "true_positive" in scan_row
    assert f"https://github.com/o/r/blob/{HEAD}/app/db.py#L12" in scan_row
    assert "**1. <code>CVE-2025-12345</code> in <code>pkgtool</code>**" in block
    assert "- AI analysis: The request handler calls the affected function with user input." in block
    assert ("**2. <code>python.sql.formatted-query</code> at <code>app/db.py&#58;12</code>**"
            in block)
    assert "- AI analysis: The query joins a request value into the SQL text." in block
    assert "Recommended fix" not in block
    # accepted scanner findings show in the scan comment only
    assert "Accepted risks" not in out and "Test inputs only." not in out
    assert (out.index("### Blocking findings") < out.index("Cleared by AI review")
            < out.index("Non-blocking findings"))
    cleared = out.split("Cleared by AI review (2)")[1].split("</details>")[0]
    assert CLEARED_HEADER[:-1] + "| AI analysis |" in cleared
    assert "not_reachable" in cleared and "false_positive" in cleared
    assert "app/requirements.txt" in cleared  # target of a dependency finding that is not reachable
    assert "The affected module is never imported." in cleared
    assert "Only a module constant reaches the query text." in cleared
    assert "A scanner finding of medium severity or higher blocks unless the AI " \
        "review clears it with high confidence (not_reachable for a dependency finding, " \
        "false_positive for a code finding) or the owner accepts it." in out
    assert "Scanners:" not in out
    assert "AI-generated by <code>m-1</code>" in out
    assert "not reviewed" not in out


def test_cleared_section_without_details():
    s = load(AI_BLOCK)
    s.pop("details")
    for e in s["triage"] + s["scan"]:
        e.pop("reason", None)
    out = report.render(s)
    cleared = out.split("Cleared by AI review (2)")[1].split("</details>")[0]
    assert "AI analysis" not in cleared and "never imported" not in out
    assert "**1. " not in out and "Recommended fix" not in out
    assert "not published" in out
    assert "Cleared by AI review" not in report.render(base_summary())


def test_baseline_mode_pass_and_block():
    out = report.render(None, "o/r", baseline=load(BASELINE_PASS), review_result="skipped")
    assert "## AI review: not run" in out
    assert ("The AI review did not run for this change. The gate result comes from the "
            "deterministic scan alone: **passed**.") in out
    assert "blocking finding(s)" not in out and "Change findings" not in out
    assert "not reviewed" not in out
    out = report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result="skipped")
    assert "## AI review: not run" in out
    assert ("The AI review did not run for this change. The gate result comes from the "
            "deterministic scan alone: **blocked**.") in out
    assert "**2 blocking finding(s).** Resolve each one." in out
    assert out.count("not reviewed") == 1
    assert "2 open scanner finding(s) were not reviewed by the AI. The Security scan comment " \
        "lists them." in out
    assert "### Blocking findings" not in out
    assert "CVE-2025-12345" not in out and "python.sql.formatted-query" not in out
    assert "Cleared by AI review" not in out
    assert "Model:" not in out and "Scanners:" not in out
    assert "<code></code>" not in out and "A change finding blocks" not in out
    # a failed baseline, skipped review
    b = {**load(BASELINE_PASS), "verdict": "ERROR", "error": "report unreadable"}
    out = report.render(None, baseline=b, review_result="skipped")
    assert "## AI review: Review incomplete" in out
    assert "**The scanner baseline did not finish:** report unreadable." in out


def test_incomplete_mode_counts_open_findings():
    for result in ("failure", "cancelled", "success", None):
        out = report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result=result)
        assert "## AI review: Review incomplete" in out
        assert ("**The AI review did not finish.** The gate fails closed, so this change is "
                "blocked until a review completes.") in out
        assert "The AI review did not run" not in out
        assert "### Blocking findings" not in out and out.count("not reviewed") == 1
        assert "2 open scanner finding(s) were not reviewed by the AI. The Security scan " \
            "comment lists them." in out
        assert "CVE-2025-12345" not in out and "python.sql.formatted-query" not in out
    out = report.render(None)
    assert "Review incomplete" in out and "### " not in out and "not reviewed" not in out


def test_ai_error_counts_baseline_findings():
    s = load(AI_BLOCK)
    s.update(verdict="ERROR", error="limit reached: triage findings", error_request_id=None,
             triage=[], scan=[])
    out = report.render(s, "o/r", baseline=load(BASELINE_BLOCK), review_result="failure")
    assert "**The review did not finish:** limit reached&#58; triage findings." in out
    assert "### Blocking findings" not in out and out.count("not reviewed") == 1
    assert "2 open scanner finding(s) were not reviewed by the AI." in out
    assert "Model: <code>m-1</code>" in out
    # without a baseline the AI summary's own entries are counted
    s2 = load(AI_BLOCK)
    s2.update(verdict="ERROR", error="x")
    out = report.render(s2)
    assert "### Blocking findings" not in out
    assert "2 open scanner finding(s) were not reviewed by the AI." in out


def test_code_scan_rows_and_accepted():
    s = base_summary(verdict="BLOCK", scan=[
        code_entry(), code_entry(key="S2", ruling="suppressed", verdict=None, confidence=None,
                                 suppression={"reason": "r", "expires": "2027-01-01"}),
        code_entry(key="S3", ruling="cleared", verdict="false_positive", file="", line=0)])
    out = report.render(s, "o/r")
    assert "| Scanner |" not in out and "Accepted risks" not in out
    assert "Cleared by AI review (1)" in out
    assert "Non-blocking findings (0)" in out
    assert "not reviewed" not in out
    assert "Scanner findings sent to the AI review: 2; 1 cleared, 1 blocking." in out


def test_hostile_scanner_strings():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    dep = scan(id="CVE-2025-1", package=evil, target=evil + big, verdict="unknown", file=evil,
               ruling="blocking")
    dep2 = scan(id="CVE-2025-2", target=evil + big, verdict="not_reachable", ruling="cleared")
    sup = scan(id="CVE-2025-3", target=evil + big, ruling="suppressed", verdict=None,
               suppression={"path": evil + big, "id": evil, "cwe": evil, "reason": evil,
                            "expires": evil})
    code1 = code_entry(tool=evil + big, rule_id=evil + big, file=evil + big, severity=evil,
                       verdict=evil, confidence=evil, reason=evil + big)
    code2 = code_entry(tool=evil, rule_id=evil, file=evil, ruling="cleared", reason=evil + big)
    code3 = code_entry(tool=evil, rule_id=evil, file=evil + big, ruling="suppressed",
                       suppression={"reason": evil + big, "expires": evil})
    s = detailed(triage=[dep, dep2, sup], scan=[code1, code2, code3],
                 scanners=[{"name": evil + big, "version": evil, "kind": evil},
                           {"name": evil, "version": evil + big, "kind": "dependency"}])
    out = report.render(s, "o/r")
    assert "<script" not in out and "`" not in out
    assert "@someone" not in out and "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200
    for ln in out.splitlines():
        if ln.startswith("- AI analysis"):
            assert ln.count("Z") <= 500
    assert "Z" * 501 not in out
    # every table row stays on one line
    assert all(ln.endswith("|") for ln in out.splitlines() if ln.startswith("|"))


def test_verdict_file_and_stdout(tmp_path):
    cases = [
        (["--summary", str(FIXTURE), "--review-result", "success"], "PASS", "Passed"),
        (["--summary", str(AI_BLOCK), "--baseline", str(BASELINE_BLOCK),
          "--review-result", "success"], "BLOCK", "Blocked"),
        (["--baseline", str(BASELINE_PASS), "--review-result", "skipped"], "PASS", "not run"),
        (["--baseline", str(BASELINE_BLOCK), "--review-result", "skipped"], "BLOCK", "not run"),
        (["--baseline", str(BASELINE_BLOCK), "--review-result", "failure"], "ERROR",
         "Review incomplete"),
        (["--summary", str(tmp_path / "missing.json"), "--baseline", str(BASELINE_PASS),
          "--review-result", "success"], "ERROR", "Review incomplete"),
        ([str(FIXTURE)], "PASS", "Passed"),
    ]
    for i, (args, verdict, heading) in enumerate(cases):
        out_file = tmp_path / f"v{i}.txt"
        r = run_cli(*args, "--verdict-out", str(out_file), "--repo", "o/r")
        assert r.returncode == 0, r.stderr
        assert out_file.read_text().strip() == verdict
        assert r.stdout.splitlines()[0] == report.MARKER
        assert f"## AI review: {heading}" in r.stdout
    # an unwritable verdict file does not stop the markdown
    r = run_cli("--summary", str(FIXTURE), "--verdict-out", str(tmp_path / "no" / "v.txt"))
    assert r.returncode == 0 and r.stdout.startswith(report.MARKER)
    assert len(r.stderr.strip().splitlines()) == 1


AI_BLOCK_OPUS = FIXTURES / "ai-block-opus-summary.json"
AI_ERROR = FIXTURES / "ai-error-summary.json"


def test_pick_summary_rules():
    p, b, e = {"verdict": "PASS", "n": 1}, {"verdict": "BLOCK", "n": 2}, {"verdict": "ERROR", "n": 3}
    assert report.pick_summary([]) == (None, False)
    assert report.pick_summary([p]) == (p, False)
    assert report.pick_summary([p, p2 := {"verdict": "PASS", "n": 4}]) == (p, False)
    assert report.pick_summary([p, b]) == (b, False)
    assert report.pick_summary([b, p]) == (b, False)
    assert report.pick_summary([p, e]) == (e, False)
    assert report.pick_summary([e, b]) == (b, False)
    assert report.pick_summary([b, e]) == (b, False)
    assert report.pick_summary([p, None]) == (None, True)
    assert report.pick_summary([p, {}]) == (None, True)
    assert report.pick_summary([None]) == (None, True)
    assert report.pick_summary([None, b]) == (b, False)
    assert report.pick_summary([None, e]) == (e, False)
    assert p2["n"] == 4


def test_reviews_line():
    s = load(AI_BLOCK_OPUS)
    out = report.render(s, reviews=[("claude-mythos-5-2", "PASS"), ("claude-opus-5-5", "BLOCK")])
    assert ("Reviews in this run: <code>claude-mythos-5-2</code> PASS, "
            "<code>claude-opus-5-5</code> BLOCK. The report below is from "
            "<code>claude-opus-5-5</code>.") in out
    assert "Reviews in this run" not in report.render(s, reviews=[("claude-opus-5-5", "BLOCK")])
    assert "Reviews in this run" not in report.render(s)
    assert "Reviews in this run" not in report.render(s, reviews=[])
    # no picked report: the line ends after the list
    out = report.render(None, reviews=[("a", "PASS"), ("b", "PASS")])
    assert "Reviews in this run: <code>a</code> PASS, <code>b</code> PASS.\n" in out
    assert "The report below" not in out


def test_reviews_line_hostile_model():
    evil = "<script>`x`|a\n::error::x @someone ](http://x)" + "Z" * 500
    out = report.render(load(AI_BLOCK_OPUS), reviews=[(evil, "PASS"), (None, "BLOCK")])
    line = [ln for ln in out.splitlines() if ln.startswith("Reviews in this run")][0]
    assert "<script" not in out and "`" not in out and "@someone" not in out
    assert "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    assert line.count("Z") <= 200
    assert "<code></code> BLOCK" in line


def test_cli_several_summaries(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    missing = tmp_path / "missing.json"
    cases = [
        ([FIXTURE], "PASS", False),
        ([FIXTURE, AI_BLOCK_OPUS], "BLOCK", True),
        ([FIXTURE, AI_ERROR], "ERROR", True),
        ([AI_ERROR, AI_BLOCK_OPUS], "BLOCK", True),
        ([FIXTURE, FIXTURE], "PASS", True),
        ([FIXTURE, bad], "ERROR", False),
        ([FIXTURE, missing], "ERROR", False),
        ([AI_BLOCK_OPUS, bad], "BLOCK", False),
    ]
    for i, (paths, verdict, line) in enumerate(cases):
        out_file = tmp_path / f"v{i}.txt"
        args = [a for p in paths for a in ("--summary", str(p))]
        r = run_cli(*args, "--baseline", str(BASELINE_PASS), "--review-result", "success",
                    "--verdict-out", str(out_file), "--repo", "o/r")
        assert r.returncode == 0, r.stderr
        assert out_file.read_text().strip() == verdict, (paths, r.stdout[:300])
        assert ("Reviews in this run" in r.stdout) == line, paths
    r = run_cli("--summary", str(FIXTURE), "--summary", str(AI_BLOCK_OPUS),
                "--verdict-out", str(tmp_path / "v.txt"))
    assert "## AI review: Blocked" in r.stdout
    assert ("Reviews in this run: <code>claude-mythos-5-2</code> PASS, "
            "<code>claude-opus-5-5</code> BLOCK. The report below is from "
            "<code>claude-opus-5-5</code>.") in r.stdout
    assert "Model: <code>claude-opus-5-5</code>" in r.stdout
    # an unreadable file among readable ones: one stderr line, error mode
    r = run_cli("--summary", str(FIXTURE), "--summary", str(bad))
    assert "Review incomplete" in r.stdout and "**The AI review did not finish.**" in r.stdout
    assert len(r.stderr.strip().splitlines()) == 1
    # the positional alias counts as one more summary
    r = run_cli(str(FIXTURE), "--summary", str(AI_BLOCK_OPUS))
    assert "Blocked" in r.stdout and "Reviews in this run" in r.stdout


def test_cli_no_summary_skipped_uses_baseline(tmp_path):
    out_file = tmp_path / "v.txt"
    r = run_cli("--baseline", str(BASELINE_BLOCK), "--review-result", "skipped",
                "--verdict-out", str(out_file))
    assert out_file.read_text().strip() == "BLOCK"
    assert "The AI review did not run for this change." in r.stdout
    assert "Reviews in this run" not in r.stdout


AI_REFUSAL = FIXTURES / "ai-refusal-summary.json"
REFUSAL_LINE = ("**{m} refused to run this security review** (stop reason: refusal{c}). The gate "
                "does not switch to another model. To get a review from another model, start a "
                "new run and write that model's ID in the approval comment.")


def refused(**kw):
    s = load(AI_REFUSAL)
    s.update(kw)
    return s


def test_single_refusal(tmp_path):
    out = report.render(load(AI_REFUSAL), reviews=[("claude-mythos-5-2", "REFUSED")])
    assert "## AI review: Review refused" in out
    line = REFUSAL_LINE.format(m="<code>claude-mythos-5-2</code>", c=", category: <code>cyber</code>")
    assert line in out
    assert "did not finish" not in out and "Review incomplete" not in out
    assert "The gate fails closed, so this change is blocked until a review completes." in out
    assert out.index("refused to run") < out.index("fails closed")
    out_file = tmp_path / "v.txt"
    r = run_cli("--summary", str(AI_REFUSAL), "--verdict-out", str(out_file))
    assert out_file.read_text().strip() == "ERROR"
    assert "## AI review: Review refused" in r.stdout and line in r.stdout
    assert "Reviews in this run" not in r.stdout


def test_refusal_without_category():
    s = refused(requests=[{"request_id": "r", "stop_reason": "refusal", "stop_category": ""}])
    out = report.render(s)
    assert REFUSAL_LINE.format(m="<code>claude-mythos-5-2</code>", c="") in out
    assert "category" not in out
    # final_stop_reason alone also counts
    s = refused(requests=[], final_stop_reason="refusal")
    assert "refused to run" in report.render(s)
    # the last request alone also counts
    s = refused(final_stop_reason="end_turn")
    assert "refused to run" in report.render(s)


def test_refusal_with_block_and_pass(tmp_path):
    r = run_cli("--summary", str(AI_REFUSAL), "--summary", str(AI_BLOCK_OPUS),
                "--verdict-out", str(tmp_path / "v.txt"))
    assert "## AI review: Blocked" in r.stdout
    assert REFUSAL_LINE.format(m="<code>claude-mythos-5-2</code>",
                               c=", category: <code>cyber</code>") in r.stdout
    assert ("Reviews in this run: <code>claude-mythos-5-2</code> REFUSED, "
            "<code>claude-opus-5-5</code> BLOCK.") in r.stdout
    assert r.stdout.index("refused to run") < r.stdout.index("Reviews in this run")
    assert (tmp_path / "v.txt").read_text().strip() == "BLOCK"
    r = run_cli("--summary", str(FIXTURE), "--summary", str(AI_REFUSAL),
                "--verdict-out", str(tmp_path / "w.txt"))
    assert "## AI review: Review refused" in r.stdout
    assert "Reviews in this run: <code>claude-mythos-5-2</code> PASS, " \
        "<code>claude-mythos-5-2</code> REFUSED." in r.stdout
    assert "refused to run" in r.stdout
    assert (tmp_path / "w.txt").read_text().strip() == "ERROR"


def test_refusal_hostile_strings():
    evil = "<script>`x`|a\n::error::x @someone ](http://x)" + "Z" * 500
    s = refused(model_requested=evil, requests=[
        {"request_id": "r", "stop_reason": "refusal", "stop_category": evil}])
    out = report.render(s)
    assert "<script" not in out and "`" not in out and "@someone" not in out
    assert "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200


def test_other_error_keeps_generic_text():
    s = base_summary(verdict="ERROR", error="limit reached: triage findings",
                     final_stop_reason="end_turn",
                     requests=[{"request_id": "r", "stop_reason": "end_turn",
                                "stop_category": None}])
    out = report.render(s)
    assert "## AI review: Review incomplete" in out
    assert "**The review did not finish:** limit reached&#58; triage findings." in out
    assert "refused" not in out
    # a PASS summary with a refusal-looking stop reason is not a refusal
    assert report.refusal(base_summary(final_stop_reason="refusal")) is None


def test_refusal_names_the_model_that_answered(tmp_path):
    s = refused(model_requested="m-req", model_returned="m-req-20261101")
    out = report.render(s)
    assert REFUSAL_LINE.format(m="<code>m-req-20261101</code>",
                               c=", category: <code>cyber</code>") in out
    assert "<code>m-req</code> refused" not in out
    p = tmp_path / "s.json"
    p.write_text(json.dumps(s))
    r = run_cli("--summary", str(p), "--summary", str(FIXTURE))
    assert "<code>m-req-20261101</code> REFUSED" in r.stdout
    # only model_requested set
    for returned in (None, ""):
        s = refused(model_requested="m-req", model_returned=returned)
        out = report.render(s)
        assert "<code>m-req</code> refused to run" in out


def sup_entry(kind="change", **sup):
    full = {"path": None, "id": None, "cwe": None, "reason": "r", "expires": "2027-01-01"}
    full.update(sup)
    if kind == "change":
        return change(ruling="suppressed", suppression=full)
    if kind == "dep":
        return scan(ruling="suppressed", suppression=full)
    return code_entry(ruling="suppressed", suppression=full)


def accepted_section(out):
    return out.split("<details><summary>Accepted risks (")[1].split("</details>")[0]


def accepted_rows(out):
    return [ln for ln in accepted_section(out).splitlines()[1:]
            if ln.startswith("| ") and not ln.startswith("| Suppression")]


def test_accepted_findings_fold_into_one_row():
    fs = [sup_entry(path="x/d", reason="why") for _ in range(229)]
    out = report.render(base_summary(findings=fs))
    assert "Accepted risks (229 finding(s) under 1 suppression(s))" in out
    rows = accepted_rows(out)
    assert len(rows) == 1
    assert rows[0] == "| path <code>x/d</code> | why | <code>2027-01-01</code> | 229 |"
    assert "more; see the summary artifact" not in out
    assert "### Accepted risks" not in out
    assert "The summary artifact of this run lists each accepted finding.\n\n</details>" in out


def test_accepted_rows_keep_first_appearance_order():
    s = base_summary(findings=[sup_entry(path="b/d"), sup_entry(path="a/d"),
                               sup_entry(path="b/d"), sup_entry(path="c/d")])
    out = report.render(s)
    assert "Accepted risks (4 finding(s) under 3 suppression(s))" in out
    rows = accepted_rows(out)
    assert [r.split("</code>")[0].split("<code>")[1] for r in rows] == ["b/d", "a/d", "c/d"]
    assert rows[0].endswith("| 2 |") and rows[1].endswith("| 1 |")
    # entries that share path and reason but differ in id are separate rows
    s = base_summary(findings=[sup_entry(path="p", id="CVE-2025-1111"),
                               sup_entry(path="p", id="CVE-2025-2222")])
    assert len(accepted_rows(report.render(s))) == 2


def test_accepted_scanner_findings_give_no_section():
    s = base_summary(triage=[sup_entry("dep", path="t/d")], scan=[sup_entry("code", path="c/d")])
    assert "Accepted risks" not in report.render(s)
    # only the accepted change finding is listed
    s["findings"] = [sup_entry(path="f/d")]
    rows = accepted_rows(report.render(s))
    assert len(rows) == 1 and "f/d" in rows[0]
    assert "Accepted risks (1 finding(s) under 1 suppression(s))" in report.render(s)


def test_accepted_suppression_cell():
    def cell(**sup):
        return accepted_rows(report.render(base_summary(findings=[sup_entry(**sup)])))[0] \
            .split(" | ")[0]
    assert cell(path="a/b") == "| path <code>a/b</code>"
    assert cell(id="CVE-2025-1111") == ("| ID [<code>CVE-2025-1111</code>]"
                                     "(https://www.cve.org/CVERecord?id=CVE-2025-1111)")
    assert cell(path="a/b", id="CVE-2025-1111") == (
        "| path <code>a/b</code>, ID [<code>CVE-2025-1111</code>]"
        "(https://www.cve.org/CVERecord?id=CVE-2025-1111)")
    assert cell(cwe="CWE-22") == ("| CWE [<code>CWE-22</code>]"
                                  "(https://cwe.mitre.org/data/definitions/22.html)")
    assert cell() == "| -"
    # a suppression that is not an object, or holds non-string values, gives no parts
    s = base_summary(findings=[change(ruling="suppressed", suppression="x"),
                               change(ruling="suppressed",
                                      suppression={"path": 5, "id": ["x"]})])
    out = report.render(s)
    assert "under 1 suppression(s))" in out
    assert accepted_rows(out)[0].startswith("| - |")


def test_no_accepted_findings_no_section():
    out = report.render(base_summary(findings=[change()], verdict="BLOCK"))
    assert "Accepted risks" not in out and "accepted risk" not in out.lower()


def test_accepted_hostile_values():
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    big = "Z" * 5000
    s = base_summary(findings=[sup_entry(path=evil + big, id=evil, cwe=evil, reason=evil + big,
                                         expires=evil + big)])
    out = report.render(s)
    assert "<script" not in out and "`" not in out and "@someone" not in out
    assert "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    assert "Z" * 301 not in out
    rows = accepted_rows(out)
    assert len(rows) == 1 and rows[0].endswith("| 1 |")
    assert all(ln.endswith("|") for ln in out.splitlines() if ln.startswith("|"))


def test_reasoned_blocks_drop_the_generic_fix_line():
    s = detailed(triage=[with_text(scan(id="CVE-2025-1111"), reason="dep reason"),
                         scan(id="CVE-2025-2222")],
                 scan=[with_text(code_entry(rule_id="r.one"), reason="code reason"),
                       code_entry(rule_id="r.two")])
    out = report.render(s, "o/r")
    blocks = re.split(r"(?m)^(?=\*\*\d+\. )", out.split("### Blocking findings")[1])[1:]
    assert len(blocks) == 4
    dep_r, dep_n, code_r, code_n = blocks
    assert "- AI analysis: dep reason" in dep_r and "Recommended fix" not in dep_r
    assert "- AI analysis: code reason" in code_r and "Recommended fix" not in code_r
    assert "AI analysis" not in dep_n and f"- Recommended fix: {report.FIX_LINE}" in dep_n
    assert "AI analysis" not in code_n and f"- Recommended fix: {report.CODE_FIX_LINE}" in code_n


def test_change_finding_keeps_its_own_fix():
    f = with_text(change(), title="T", impact="I", fix="Do this.")
    out = report.render(detailed(findings=[f]), "o/r")
    assert "- Recommended fix: Do this." in out and "- Impact: I" in out
    assert report.FIX_LINE not in out and report.CODE_FIX_LINE not in out


def test_refusal_line_new_sentence():
    line = report.refusal_line("m", None)
    assert line.endswith("To get a review from another model, start a new run and write "
                         "that model's ID in the approval comment.")
    assert "approve a different model" not in line


def dep(**kw):
    return scan(**{"installed_version": "1.2.3", "fixed_version": "1.2.4",
                   "target": "req.txt", "severity": "high", **kw})


def scanner_rows(out):
    block = out.split("| Scanner | Findings | Accepted by owner | Open |")[1]
    lines = block.split("\n\n")[0].splitlines()[2:]
    return [[c.strip() for c in ln.strip("|").split(" | ")] for ln in lines]


def sup(**kw):
    return {"reason": "r", "expires": "2027-01-01", **kw}


def scan_out(baseline, **kw):
    return report.render_scan(baseline, "o/r", **kw)


def blocked(**kw):
    return base_summary(verdict="BLOCK", **kw)


def test_scan_table_counts_and_place():
    s = blocked(
        triage=[dep(), dep(), dep(ruling="suppressed", suppression=sup())],
        scan=[code_entry(), code_entry(ruling="suppressed", suppression=sup()),
              code_entry(tool="other-sast", ruling="blocking")],
        scanners=[{"name": "Trivy", "version": "9.9", "kind": "dependency"},
                  {"name": "example-sast", "version": "1.0", "kind": "code"},
                  {"name": "idle", "version": "2", "kind": "code"}])
    out = scan_out(s)
    assert "| Scanner | Findings | Accepted by owner | Open |" in out
    assert scanner_rows(out) == [
        ["Dependency scan <code>Trivy 9.9</code>", "3", "1", "2"],
        ["Code scan <code>example-sast 1.0</code>", "2", "1", "1"],
        ["Code scan <code>idle 2</code>", "0", "0", "0"],
        ["Code scan <code>other-sast</code>", "1", "0", "1"]]
    rows = scanner_rows(out)
    assert all(int(r[1]) == int(r[2]) + int(r[3]) for r in rows)
    totals = [sum(int(r[i]) for r in rows) for i in (1, 2, 3)]
    assert totals == [6, 2, 4]
    assert "6 finding(s) of medium severity or higher: 2 accepted by the owner, 4 open." in out
    assert out.index("| Scanner |") < out.index("### Open findings")


def test_scan_table_kind_rules():
    # no kind counts as code; no dependency scanner named gives a bare label
    s = blocked(triage=[dep()], scanners=[{"name": "old-sast", "version": "1"}])
    rows = scanner_rows(scan_out(s))
    assert rows[0][0] == "Dependency scan"
    assert rows[1][0] == "Code scan <code>old-sast 1</code>"
    # a dependency scanner with no findings keeps its row of zeros
    s = base_summary(scanners=[{"name": "Trivy", "version": "9.9", "kind": "dependency"}])
    assert scanner_rows(scan_out(s)) == [["Dependency scan <code>Trivy 9.9</code>", "0", "0", "0"]]
    # no scanner and no finding: no table
    assert "| Scanner |" not in scan_out(base_summary())


def test_scan_markers_differ():
    out = scan_out(base_summary())
    assert out.splitlines()[0] == report.SCAN_MARKER == "<!-- security-scan-report -->"
    assert report.render(base_summary()).splitlines()[0] == report.MARKER
    assert report.SCAN_MARKER != report.MARKER
    assert not report.SCAN_MARKER.startswith(report.MARKER)
    assert not report.MARKER.startswith(report.SCAN_MARKER)


def test_scan_headings_and_status():
    out = scan_out(blocked(triage=[dep(), dep()], scan=[code_entry()]))
    assert "## Security scan: 3 open finding(s)\n" in out
    assert ("Each open finding blocks this change unless the AI review clears it or the "
            "repository owner accepts it.") in out
    out = scan_out(base_summary())
    assert "## Security scan: no open findings\n" in out
    assert "No scanner finding is open." in out
    for b in (base_summary(verdict="ERROR", error="report unreadable"), None,
              base_summary(verdict="MAYBE")):
        out = scan_out(b)
        assert "## Security scan: did not finish\n" in out
        assert "The gate fails closed, so this change is blocked until a scan completes." in out
        assert "### Open findings" not in out and "| Scanner |" not in out
        assert "finding(s) of" not in out and "This comment holds scanner results" not in out
    assert ("**The scan did not finish:** report unreadable. The gate fails closed, so this "
            "change is blocked until a scan completes.") in scan_out(
                base_summary(verdict="ERROR", error="report unreadable"))
    assert "**The scan did not finish.** The gate fails closed" in scan_out(
        base_summary(verdict="ERROR", error=None))


def test_scan_meta_and_ai_review_line():
    out = scan_out(base_summary(), run_url="https://github.com/o/r/actions/runs/5")
    assert f"<code>{BASE[:7]}</code>..<code>{HEAD[:7]}</code> | " \
        "[run](https://github.com/o/r/actions/runs/5)" in out
    assert ("The AI review posts its result in a separate comment when the review job ends. "
            f"Until that comment names <code>{HEAD[:7]}</code>, this change has not passed the "
            "gate.") in out
    out = scan_out(base_summary(head="not-a-sha", base="zz"), run_url="https://evil.example/x")
    assert "Until that comment names this commit, this change has not passed the gate." in out
    assert "..<code>" not in out and "[run]" not in out and "evil.example" not in out


def test_scan_open_findings_fold():
    out = scan_out(blocked(triage=[dep(id="CVE-2025-1"), dep(id="CVE-2025-2")]))
    assert "### Open findings" in out and "<details><summary>Open findings" not in out
    assert "| Flagged by | Finding | Severity | Location |" in out
    open_rows = [ln for ln in out.split("### Open findings")[1].splitlines()
                 if ln.startswith("| ") and "CVE-" in ln]
    assert len(open_rows) == 2 and all(r.count(" | ") == 3 for r in open_rows)
    ten = scan_out(blocked(triage=[dep(id=f"CVE-2025-{i}") for i in range(10)]))
    assert "### Open findings" in ten and "<details><summary>Open findings" not in ten
    out = scan_out(blocked(triage=[dep(id=f"CVE-2025-{i}") for i in range(11)]))
    assert "<details><summary>Open findings (11)</summary>" in out
    assert "### Open findings" not in out
    assert out.count("CVE-2025-") >= 11 and "</details>" in out


def test_scan_rows_dependency_first_then_code():
    s = blocked(triage=[dep(id="CVE-2025-1111", fixed_version="1.2.4"),
                        dep(id="CVE-2025-2222", ruling="cleared"),
                        dep(id="CVE-2025-3333", ruling="suppressed", suppression=sup())],
                scan=[code_entry()],
                scanners=[{"name": "Trivy", "version": "9", "kind": "dependency"}])
    out = scan_out(s)
    shown = out.split("### Open findings")[1].split("<details>")[0]
    rows = [ln for ln in shown.splitlines() if ln.startswith("| ") and "Flagged" not in ln]
    assert len(rows) == 2
    dep_row, code_row = rows
    assert "https://www.cve.org/CVERecord?id=CVE-2025-1111" in dep_row
    assert "<code>pkgtool 1.2.3</code>, fixed in <code>1.2.4</code>" in dep_row
    assert dep_row.startswith("| <code>Trivy</code> |")
    assert code_row.startswith("| <code>example-sast</code> | <code>python.sql.formatted-query")
    assert "no fixed version listed" in scan_out(blocked(triage=[dep(fixed_version="")]))
    assert "CVE-2025-2222" not in shown and "CVE-2025-3333" not in shown


def test_scan_accepted_risks_fold():
    fs = [dep(ruling="suppressed", suppression=sup(path="x/d")) for _ in range(5)]
    cs = [code_entry(ruling="suppressed", suppression=sup(path="c/d"))]
    out = scan_out(blocked(triage=fs + [dep(ruling="suppressed", suppression=sup(path="y/d"))],
                           scan=cs))
    assert "Accepted risks (7 finding(s) under 3 suppression(s))" in out
    rows = accepted_rows(out)
    assert len(rows) == 3
    assert rows[0] == "| path <code>x/d</code> | r | <code>2027-01-01</code> | 5 |"
    assert "Accepted risks" not in scan_out(base_summary())


def test_scan_warnings():
    out = scan_out(base_summary(notice="x", expired_suppressions=[
        {"path": None, "id": "CVE-2025-1111", "cwe": None, "reason": "r",
         "expires": "2026-01-01"}]))
    assert "Warning: the base commit holds no gate config." in out
    assert "has expired" in out and "CVE-2025-1111" in out


def test_scan_never_holds_ai_text():
    s = blocked(
        triage=[dep(verdict="reachable", reason="SENTINEL-REASON"),
                dep(ruling="suppressed", suppression=sup(), verdict=None)],
        scan=[code_entry(verdict="true_positive", confidence="high", reason="SENTINEL-REASON"),
              code_entry(ruling="cleared", verdict="false_positive")],
        details=True, findings=[change(title="SENTINEL-TITLE")])
    for out in (scan_out(s), scan_out(base_summary())):
        for word in ("not reviewed", "AI verdict", "Cleared by AI", "Model:", "AI analysis",
                     "SENTINEL"):
            assert word not in out, word
    assert ("This comment holds scanner results only: the advisory or rule ID, severity, and "
            "location. It holds no AI-written text.") in scan_out(s)


def test_scan_hostile_strings():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    s = blocked(
        error=evil, notice=evil,
        triage=[dep(id=evil + big, package=evil + big, target=evil + big,
                    installed_version=evil, fixed_version=evil + big, severity=evil),
                dep(ruling="suppressed", suppression={"path": evil + big, "id": evil,
                                                      "cwe": evil, "reason": evil + big,
                                                      "expires": evil})],
        scan=[code_entry(tool=evil + big, rule_id=evil + big, file=evil + big, severity=evil)],
        scanners=[{"name": evil, "version": evil + big, "kind": "dependency"}],
        expired_suppressions=[{"id": evil, "path": evil, "expires": evil}],
        limits={"triage_min_severity": evil})
    out = scan_out(s)
    assert "<script" not in out and "`" not in out and "@someone" not in out
    assert "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200
    assert all(ln.endswith("|") for ln in out.splitlines() if ln.startswith("|"))
    bad = scan_out(base_summary(verdict="ERROR", error=evil + big))
    assert "<script" not in bad and "@someone" not in bad and "Z" * 301 not in bad
    assert not any(ln.startswith("::") for ln in bad.splitlines())


def test_scan_size_cap():
    out = scan_out(blocked(triage=[dep(id="X" * 190 + str(i)) for i in range(1000)],
                           scan=[code_entry(file="f" * 150 + str(i)) for i in range(1000)]))
    assert len(out) <= 60000


def test_scan_cli(tmp_path):
    verdict = tmp_path / "v.txt"
    r = run_cli("--part", "scan", "--baseline", str(BASELINE_BLOCK), "--repo", "o/r",
                "--run-url", "https://github.com/o/r/actions/runs/5",
                "--summary", str(tmp_path / "ignored.json"), "--review-result", "failure",
                "--verdict-out", str(verdict))
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines()[0] == report.SCAN_MARKER
    assert "## Security scan: 2 open finding(s)" in r.stdout
    assert "[run](https://github.com/o/r/actions/runs/5)" in r.stdout
    assert not verdict.exists()
    r = run_cli("--part", "scan", "--baseline", str(tmp_path / "missing.json"),
                "--verdict-out", str(verdict))
    assert r.returncode == 0
    assert "## Security scan: did not finish" in r.stdout and not verdict.exists()
    r = run_cli("--part", "scan")
    assert r.returncode == 0 and "did not finish" in r.stdout
    # the default part is review
    r = run_cli("--summary", str(FIXTURE))
    assert r.stdout.splitlines()[0] == report.MARKER


def test_review_has_no_scanner_table_or_deterministic_line():
    cases = [report.render(load(AI_BLOCK), "o/r", baseline=load(BASELINE_BLOCK),
                           review_result="success"),
             report.render(real(), "o/r"),
             report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result="skipped"),
             report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result="failure"),
             report.render(None),
             report.render(load(AI_REFUSAL), baseline=load(BASELINE_BLOCK),
                           review_result="failure")]
    for out in cases:
        assert "| Scanner |" not in out and "Deterministic scan:" not in out
        assert out.splitlines()[2].startswith("## AI review: ")


def test_review_reviewed_scanner_line():
    out = report.render(load(AI_BLOCK), "o/r", baseline=load(BASELINE_BLOCK),
                        review_result="success")
    assert "Scanner findings sent to the AI review: 4; 2 cleared, 2 blocking.\n" in out
    s = base_summary(verdict="PASS", triage=[scan(ruling="cleared", verdict="not_reachable"),
                                             scan(ruling="note", verdict="not_reachable")],
                     scan=[code_entry(ruling="cleared", verdict="false_positive"),
                           code_entry(ruling="suppressed", suppression=sup())])
    assert "Scanner findings sent to the AI review: 3; 3 cleared, 0 blocking." in report.render(s)


def test_review_not_reviewed_modes():
    base = load(BASELINE_BLOCK)
    line = ("2 open scanner finding(s) were not reviewed by the AI. The Security scan comment "
            "lists them.")
    ai_err = load(AI_BLOCK)
    ai_err.update(verdict="ERROR", error="x", triage=[], scan=[])
    cases = [report.render(None, "o/r", baseline=base, review_result="skipped"),
             report.render(None, "o/r", baseline=base, review_result="failure"),
             report.render(ai_err, "o/r", baseline=base, review_result="failure"),
             report.render(load(AI_REFUSAL), baseline=base, review_result="failure")]
    for out in cases:
        assert line in out
        assert "### Blocking findings" not in out and "AI verdict" not in out
        assert "CVE-" not in out and "formatted-query" not in out
    # no open entry: no line
    for out in (report.render(None, baseline=load(BASELINE_PASS), review_result="skipped"),
                report.render(None, baseline=load(BASELINE_PASS), review_result="failure")):
        assert "were not reviewed" not in out
    assert "were not reviewed" not in report.render(None)
    # a failed baseline gives the old text and no scanner line
    b = {**load(BASELINE_PASS), "verdict": "ERROR", "error": "x"}
    out = report.render(None, baseline=b, review_result="skipped")
    assert "were not reviewed" not in out and "Scanner findings sent" not in out


def test_review_accepted_risks_from_change_findings_only():
    s = base_summary(triage=[sup_entry("dep", path="t/d")], scan=[sup_entry("code", path="c/d")])
    assert "Accepted risks" not in report.render(s)
    s["findings"] = [sup_entry(path="f/d")]
    out = report.render(s)
    assert "Accepted risks (1 finding(s) under 1 suppression(s))" in out
    out = report.render(None, baseline={**base_summary(verdict="BLOCK"),
                                        "triage": [sup_entry("dep", path="t/d")]},
                        review_result="skipped")
    assert "Accepted risks" not in out


def test_table_headers():
    out = report.render(load(AI_BLOCK), "o/r", baseline=load(BASELINE_BLOCK),
                        review_result="success")
    assert BLOCKING_HEADER in out
    assert CLEARED_HEADER[:-1] + "| AI analysis |" in out
    out = report.render(base_summary(triage=[scan(ruling="cleared", verdict="not_reachable")]))
    assert CLEARED_HEADER in out and "AI analysis" not in out


def test_dependency_row_cells():
    s = base_summary(verdict="BLOCK", triage=[
        dep(id="CVE-2025-1111"), dep(id="CVE-2025-2222", fixed_version=""),
        scan(id="CVE-2025-3333", package=None)],
        scanners=[{"name": "Trivy", "version": "9", "kind": "dependency"}])
    out = report.render(s, "o/r")
    one, two, three = [ln for ln in out.splitlines() if ln.startswith("| ") and "CVE-" in ln
                       and "Flagged" not in ln][:3]
    assert "<code>pkgtool 1.2.3</code>, fixed in <code>1.2.4</code>" in one
    assert "https://www.cve.org/CVERecord?id=CVE-2025-1111" in one
    assert "<code>Trivy</code>" in one
    assert "no fixed version listed" in two and "fixed in" not in two
    assert three.split(" | ")[2].endswith("(https://www.cve.org/CVERecord?id=CVE-2025-3333)")
    out = report.render(base_summary(verdict="BLOCK", triage=[dep()]))
    assert "| 1 | Dependency scan | " in out


def test_dependency_reachable_goes_to_verdict_cell():
    s = base_summary(verdict="BLOCK", triage=[
        dep(id="CVE-2025-1", verdict="reachable", file="app/app.py", line=23),
        dep(id="CVE-2025-2", verdict="not_reachable", file="app/app.py", line=23)])
    out = report.render(s, "o/r")
    r1, r2 = [ln for ln in out.splitlines() if ln.startswith("| ") and "CVE-" in ln]
    cells = r1.strip("| ").split(" | ")
    assert cells[4] == "<code>req.txt</code>"
    assert cells[5].startswith("reachable at [<code>app/app.py&#58;23</code>]")
    assert f"/blob/{HEAD}/app/app.py#L23" in cells[5]
    cells = r2.strip("| ").split(" | ")
    assert cells[4] == "<code>req.txt</code>" and cells[5] == "not_reachable"
    assert " at " not in r2


def test_code_and_change_row_cells():
    s = base_summary(verdict="BLOCK", findings=[change()], scan=[code_entry()])
    out = report.render(s, "o/r")
    change_row, code_row = [ln for ln in out.splitlines() if ln.startswith("| ") and
                            ("CWE-22" in ln or "formatted-query" in ln)][:2]
    assert change_row.startswith("| 1 | AI review | [<code>CWE-22</code>]")
    assert code_row.startswith("| 2 | <code>example-sast</code> | <code>python.sql.formatted-query")


def test_run_details_has_no_scanners_line():
    out = report.render(base_summary(scanners=[{"name": "a", "version": "1", "kind": "code"}]))
    assert "Run details" in out and "Scanners:" not in out


def test_hostile_dependency_fields():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    s = base_summary(verdict="BLOCK",
                     triage=[dep(installed_version=evil + big, fixed_version=evil + big)],
                     scan=[code_entry(tool=evil + big), code_entry(tool=5)],
                     scanners=[{"name": evil, "version": evil + big, "kind": "dependency"},
                               {"name": evil + big, "version": evil, "kind": "code"}])
    out = report.render(s, "o/r")
    assert "<script" not in out and "`" not in out and "@someone" not in out
    assert "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200
    assert all(ln.endswith("|") for ln in out.splitlines() if ln.startswith("|"))


F1_LINE = ("The review job of this attempt failed. This result comes from an earlier attempt "
           "of the same run.")
F2_LINE = "A scanner finding stays blocking unless the AI review clears it with high confidence."


def test_stale_attempt_line():
    out = report.render(base_summary(), review_result="failure")
    assert F1_LINE in out
    assert out.index("No finding blocks this change.") < out.index(F1_LINE) \
        < out.index("Change findings")
    for verdict, result in (("BLOCK", "failure"), ("ERROR", "failure"), ("PASS", "success"),
                            ("PASS", None), ("PASS", "skipped")):
        s = base_summary(verdict=verdict, error="x" if verdict == "ERROR" else None,
                         findings=[change()] if verdict == "BLOCK" else [])
        assert F1_LINE not in report.render(s, review_result=result), (verdict, result)
    out = report.render(None, baseline=load(BASELINE_PASS), review_result="skipped")
    assert F1_LINE not in out


def test_clear_rule_sentence():
    for entry in (dep(verdict="not_reachable", confidence="medium"),
                  code_entry(verdict="false_positive", confidence="medium")):
        key = "triage" if "package" in entry else "scan"
        out = report.render(detailed(**{key: [with_text(entry, reason="why")]}), "o/r")
        assert out.count(F2_LINE) == 1
        assert out.index("| 1 |") < out.index(F2_LINE) < out.index("**1. ")
    s = detailed(triage=[dep(verdict="reachable")],
                 scan=[code_entry(verdict="true_positive"), code_entry(verdict="unknown")],
                 findings=[change()])
    assert F2_LINE not in report.render(s, "o/r")
    out = report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result="skipped")
    assert "### Blocking findings" not in out and F2_LINE not in out


def test_cut_values_end_with_dots():
    out = report.render(detailed(triage=[with_text(scan(), reason="Q" * 600)]), "o/r")
    line = [ln for ln in out.splitlines() if ln.startswith("- AI analysis: ")][0]
    assert line == "- AI analysis: " + "Q" * 497 + "..."
    out = report.render(detailed(triage=[with_text(scan(), reason="Q" * 500)]), "o/r")
    assert "- AI analysis: " + "Q" * 500 + "\n" in out and "Q" * 500 + "..." not in out
    # the cut comes before escaping, so an escaped character is never split
    out = report.render(detailed(triage=[with_text(scan(), reason="Q" * 496 + ":::::")]), "o/r")
    line = [ln for ln in out.splitlines() if ln.startswith("- AI analysis: ")][0]
    assert line == "- AI analysis: " + "Q" * 496 + "&#58;..."
    assert report._clean("abc", 3) == "abc" and report._clean("abcd", 3) == "..."


PROOF_DIR = FIXTURES / "proof"
MYTHOS_PROOF = PROOF_DIR / "mythos-block-summary.json"
FABLE_PROOF = PROOF_DIR / "fable-refused-summary.json"
PROOF_HEADER = BLOCKING_HEADER[:-1] + "| Proof |"
PROOF_LINE_TAIL = ("A proof test passes only when it shows the flaw on the running app. A finding "
                   "blocks with or without one. The test code is not published.")


def proof_summary(entries, findings=None, triage=None, **kw):
    return base_summary(verdict="BLOCK", findings=findings or [], triage=triage or [],
                        proof={"stage": "completed", "entries": entries, "requests": [],
                               "totals": {}}, **kw)


def proof_cells(out):
    rows = [ln for ln in out.splitlines() if ln.startswith("| ") and "Flagged" not in ln]
    return [ln.strip("| ").split(" | ")[-1] for ln in rows]


def test_proof_column_and_cell_values():
    s = proof_summary(
        [{"n": 1, "outcome": "written"}, {"n": 2, "outcome": "written"},
         {"n": 3, "outcome": "written"}, {"n": 4, "outcome": "written"},
         {"n": 5, "outcome": "invalid"}],
        findings=[change(proof=1), change(proof=2), change(proof=3), change(proof=4),
                  change(proof=5), change()])
    results = {1: "confirmed", 2: "not_confirmed", 3: "error"}
    out = report.render(s, "o/r", proof_results=results)
    assert PROOF_HEADER in out
    assert proof_cells(out) == ["confirmed", "not confirmed", "error", "not run",
                                "no valid test", "-"]
    line = (f"Proof tests: 4 written by <code>m-1</code> and run against the app in a container "
            f"with no outside network: 1 confirmed, 1 not confirmed, 1 error. {PROOF_LINE_TAIL}")
    assert line in out
    assert out.index(line) < out.index(PROOF_HEADER)
    assert out.index("### Blocking findings") < out.index(line)
    # dependency and code rows carry the column too
    s = proof_summary([{"n": 1, "outcome": "written"}], triage=[scan(proof=1)],
                      scan=[code_entry()])
    assert proof_cells(report.render(s, proof_results={1: "confirmed"})) == ["confirmed", "-"]


def test_no_proof_renders_as_before():
    plain = base_summary(verdict="BLOCK", findings=[change()])
    out = report.render(plain)
    assert BLOCKING_HEADER in out and "Proof" not in out
    for proof in (None, {"stage": "completed", "entries": [], "requests": [], "totals": {}}):
        assert report.render(dict(plain, proof=proof)) == out
    # results alone, without proof entries, change nothing
    assert report.render(plain, proof_results={1: "confirmed"}) == out


def test_proof_results_filter():
    hostile = {"results": [
        {"n": 1, "outcome": "confirmed"}, {"n": "2", "outcome": "confirmed"},
        {"n": True, "outcome": "confirmed"}, {"n": 3, "outcome": "<b>pwned</b>"},
        {"n": 4, "outcome": "passed"}, {"n": 5, "outcome": ["confirmed"]},
        {"n": 10 ** 40, "outcome": "confirmed"}, {"n": 6, "outcome": "[x](http://e.com)"},
        {"n": 1, "outcome": "error"}, "junk", {"outcome": "confirmed"}, {"n": 7}]}
    assert report.clean_results(hostile) == {1: "confirmed", 10 ** 40: "confirmed"}
    assert report.clean_results({"results": "x"}) == {}
    assert report.clean_results([1]) == {}
    # a hostile value that slips through render() never reaches the comment
    s = proof_summary([{"n": 3, "outcome": "written"}], findings=[change(proof=3)])
    out = report.render(s, proof_results={3: "<b>pwned</b>", "x": "confirmed"})
    assert "pwned" not in out and proof_cells(out) == ["not run"]


def test_hostile_proof_entries():
    s = proof_summary([{"n": 1, "outcome": "<img src=x>"}, {"n": "2", "outcome": "written"},
                       {"n": 3, "outcome": "written"}, "junk"],
                      findings=[change(proof=1), change(proof="2"), change(proof=3),
                                change(proof=True), change(proof=99)])
    out = report.render(s)
    assert "<img" not in out
    assert proof_cells(out) == ["-", "-", "not run", "-", "-"]
    assert "Proof tests: 1 written by" in out


def test_proof_results_cli_hostile_file(tmp_path):
    summary = tmp_path / "s.json"
    summary.write_text(json.dumps(proof_summary(
        [{"n": 1, "outcome": "written"}, {"n": 2, "outcome": "written"}],
        findings=[change(proof=1), change(proof=2)])))
    res = tmp_path / report.PROOF_RESULTS_NAME
    res.write_text(json.dumps({"results": [
        {"n": 1, "outcome": "confirmed"}, {"n": 2, "outcome": "<script>x</script>"},
        {"n": 10 ** 30, "outcome": "confirmed"}, {"n": "1", "outcome": "error"}]}))
    r = run_cli("--summary", str(summary))
    assert proof_cells(r.stdout) == ["confirmed", "not run"]
    assert "<script" not in r.stdout and "1 confirmed, 0 not confirmed, 0 error" in r.stdout
    for body in ("not json", "[1]"):
        res.write_text(body)
        r = run_cli("--summary", str(summary))
        assert r.returncode == 0 and proof_cells(r.stdout) == ["not run", "not run"]
        assert len(r.stderr.strip().splitlines()) == 1
    res.unlink()
    r = run_cli("--summary", str(summary))
    assert r.stderr == "" and proof_cells(r.stdout) == ["not run", "not run"]


def test_proof_refusal_line():
    s = load(FABLE_PROOF)
    out = report.render(s, reviews=[("claude-fable-5-2", "REFUSED")])
    assert "## AI review: Review refused" in out
    assert ("**<code>claude-fable-5-2</code> refused to write a proof test for this review** "
            "(stop reason: refusal, category: <code>cyber</code>). The triage finished. The "
            "model declined the request for a read-only test that confirms or refutes "
            "<code>CVE-2026-48817</code> on the running app. The gate does not switch to "
            "another model. To get a review from another model, start a new run and write "
            "that model's ID in the approval comment.") in out
    assert "refused to run this security review" not in out
    assert "The gate fails closed, so this change is blocked until a review completes." in out
    # the proof 1 entry may be a change finding or a code entry
    s = load(FABLE_PROOF)
    s["triage"], s["findings"] = [], [change(cwe="CWE-89", proof=1)]
    assert "refutes <code>CWE-89</code> on the running app" in report.render(s)
    # no proof 1 entry in the summary
    s["findings"] = []
    assert "refutes this finding on the running app" in report.render(s)
    # no category on the last proof request
    s["proof"]["requests"] = [{"request_id": "r", "stop_reason": "refusal", "stop_category": ""}]
    assert "category" not in report.render(s)


def test_review_refusal_keeps_its_line_even_with_proof_refused():
    out = report.render(load(AI_REFUSAL))
    assert "refused to run this security review" in out and "proof test" not in out
    s = load(FABLE_PROOF)
    s["requests"] = [{"request_id": "r", "stop_reason": "refusal", "stop_category": "cyber"}]
    out = report.render(s)
    assert "refused to run this security review" in out and "proof test" not in out
    # a proof stage "refused" on a verdict that is not ERROR is no refusal
    s = load(FABLE_PROOF)
    s["verdict"] = "BLOCK"
    assert report.refusal(s) is None


def test_two_summaries_fable_refused_mythos_block(tmp_path):
    out_file = tmp_path / "v.txt"
    for order in ((FABLE_PROOF, MYTHOS_PROOF), (MYTHOS_PROOF, FABLE_PROOF)):
        r = run_cli("--summary", str(order[0]), "--summary", str(order[1]),
                    "--verdict-out", str(out_file), "--repo", "o/r")
        assert r.returncode == 0, r.stderr
        out = r.stdout
        assert out_file.read_text().strip() == "BLOCK"
        assert "## AI review: Blocked" in out
        assert "<code>claude-fable-5-2</code> refused to write a proof test for this review" in out
        assert ("Reviews in this run: <code>claude-fable-5-2</code> REFUSED, "
                "<code>claude-mythos-5-2</code> BLOCK" in out
                or "Reviews in this run: <code>claude-mythos-5-2</code> BLOCK, "
                "<code>claude-fable-5-2</code> REFUSED" in out)
        assert "Model: <code>claude-mythos-5-2</code>" in out
        assert PROOF_HEADER in out
        assert proof_cells(out) == ["confirmed", "confirmed", "not confirmed", "-",
                                    "no valid test"]
        assert "Proof tests: 3 written by <code>claude-mythos-5-2</code>" in out
        assert "2 confirmed, 1 not confirmed, 0 error" in out
        assert out.index("refused to write") < out.index("Reviews in this run")
    # the comment holds no model-written proof text
    assert "test_proof" not in out and "pytest" not in out


def test_scan_comment_unchanged_by_proof():
    baseline = load(BASELINE_BLOCK)
    assert "Proof" not in report.render_scan(baseline)
    s = load(MYTHOS_PROOF)
    assert report.final_verdict(s, None, "success") == ("BLOCK", "ai")
