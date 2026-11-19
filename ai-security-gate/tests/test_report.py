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
    assert "## AI Security Gate: Passed" in out
    assert "### Blocking findings" not in out
    sup = out.split("### Accepted risks")[1].split("<details>")[0]
    rows = [ln for ln in sup.splitlines() if ln.startswith("| ") and "CVE-" in ln]
    assert len(rows) == 1
    assert "CVE-2026-48817" in rows[0] and "app/app.py&#58;23" in rows[0]
    assert "Risk accepted by the service owner until the upgrade to the fixed release ships." \
        in rows[0]
    assert "2027-05-18" in rows[0]
    # the fixture predates the ruling "cleared"; its ten "note" entries read as cleared
    assert "Cleared by AI review (10)" in out and "Non-blocking findings (0)" in out
    assert "| Details |" not in out and "| Analysis |" not in out
    assert "Finding descriptions are not published for this repository." in out
    for word in ("Deliberate", "on purpose", "Suppressed"):
        assert word not in out
    assert "45105" in out and "2867" in out


def test_block_order():
    s = base_summary(verdict="BLOCK", findings=[change()], triage=[scan(id="CVE-2025-99999")])
    s["triage"].append(scan(id="CVE-2025-11111", ruling="suppressed",
                            suppression={"reason": "r", "expires": "2027-01-01"}))
    out = report.render(s, "o/r")
    b, sp, d = (out.index("### Blocking findings"), out.index("### Accepted risks"),
                out.index("<details>"))
    assert b < sp < d
    blocking = out[b:sp]
    assert "CWE-22" in blocking and "CVE-2025-99999" in blocking
    assert "| # | Source | Severity | CWE or ID | Package | AI verdict | Confidence | Location |" in blocking
    assert "Code change" in blocking and "Dependency scan" in blocking
    assert "## AI Security Gate: Blocked" in out
    assert "**2 blocking finding(s).** Resolve each one." in out


def test_error():
    s = base_summary(verdict="ERROR", error="boom happened", error_request_id="req_abc123")
    out = report.render(s)
    assert "## AI Security Gate: Review incomplete" in out
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
        assert r.returncode == 0 and "## AI Security Gate: Review incomplete" in r.stdout
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
    assert "- Analysis: The route calls the affected function." in out
    assert ("- Recommended fix: upgrade the package to a release that fixes this advisory, "
            "or remove the code path that reaches it.") in out
    notes = out.split("Non-blocking findings (1)")[1].split("</details>")[0]
    assert "| Details |" in notes and "Minor note title" in notes
    cleared = out.split("Cleared by AI review (1)")[1].split("</details>")[0]
    assert "| Analysis |" in cleared and "Never imported." in cleared
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
    assert zs == {200 - pre, 500 - pre, 300 - pre}
    title = [ln for ln in out.splitlines() if ln.startswith("**1. ")][0]
    assert title.count("Z") == 200 - pre
    impact = [ln for ln in out.splitlines() if ln.startswith("- Impact: ")][0]
    assert impact.count("Z") == 500 - pre


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
    assert "## AI Security Gate: Blocked" in out
    assert "**2 blocking finding(s).** Resolve each one." in out
    assert "Change findings: 0 blocking, 0 accepted, 0 notes." in out
    assert ("Deterministic scan: 6 finding(s) of medium severity or higher; "
            "2 accepted by the owner, 2 cleared by the AI review, 2 blocking.") in out
    block = out.split("### Blocking findings")[1].split("### Accepted risks")[0]
    rows = [ln for ln in block.splitlines() if ln.startswith("| ") and "Source" not in ln]
    assert len(rows) == 2
    dep, scan_row = rows
    assert "Dependency scan" in dep and "CVE-2025-12345" in dep and "reachable" in dep
    assert "app/app.py&#58;23" in dep and "requirements.txt" not in dep
    assert "Code scan <code>example-sast</code>" in scan_row
    assert "python.sql.formatted-query" in scan_row and "true_positive" in scan_row
    assert f"https://github.com/o/r/blob/{HEAD}/app/db.py#L12" in scan_row
    assert "**1. <code>CVE-2025-12345</code> in <code>pkgtool</code>**" in block
    assert "- Analysis: The request handler calls the affected function with user input." in block
    assert ("**2. <code>python.sql.formatted-query</code> at <code>app/db.py&#58;12</code>**"
            in block)
    assert "- Analysis: The query joins a request value into the SQL text." in block
    assert ("- Recommended fix: change the code so that the rule no longer applies. If the "
            "finding is wrong for this code, the repository owner can accept it in the "
            "gate's config file.") in block
    accepted = out.split("### Accepted risks")[1].split("<details>")[0]
    assert "CVE-2025-33333" in accepted and "generic.secrets.token" in accepted
    assert "Test inputs only." in accepted and "Sample text&#44; not a secret." in accepted
    assert (out.index("### Blocking findings") < out.index("### Accepted risks")
            < out.index("Cleared by AI review") < out.index("Non-blocking findings"))
    cleared = out.split("Cleared by AI review (2)")[1].split("</details>")[0]
    assert "| Source | CWE or ID | Package | Severity | AI verdict | Confidence | Location " \
        "| Analysis |" in cleared
    assert "not_reachable" in cleared and "false_positive" in cleared
    assert "app/requirements.txt" in cleared  # target of a dependency finding that is not reachable
    assert "The affected module is never imported." in cleared
    assert "Only a module constant reaches the query text." in cleared
    assert "A scanner finding of medium severity or higher blocks unless the AI " \
        "review clears it with high confidence (not_reachable for a dependency finding, " \
        "false_positive for a code finding) or the owner accepts it." in out
    assert "- Scanners: <code>dep-scanner 1.2.3</code>, <code>example-sast 1.0.0</code>" in out
    assert "AI-generated by <code>m-1</code>" in out
    assert "not reviewed" not in out


def test_cleared_section_without_details():
    s = load(AI_BLOCK)
    s.pop("details")
    for e in s["triage"] + s["scan"]:
        e.pop("reason", None)
    out = report.render(s)
    cleared = out.split("Cleared by AI review (2)")[1].split("</details>")[0]
    assert "| Analysis |" not in cleared and "never imported" not in out
    assert "**1. " not in out and "Recommended fix" not in out
    assert "not published" in out
    assert "Cleared by AI review" not in report.render(base_summary())


def test_baseline_mode_pass_and_block():
    out = report.render(None, "o/r", baseline=load(BASELINE_PASS), review_result="skipped")
    assert "## AI Security Gate: Passed" in out
    assert ("The AI review did not run for this change. This result comes from the "
            "deterministic scanners alone.") in out
    assert "blocking finding(s)" not in out and "Change findings" not in out
    assert ("Deterministic scan: 0 finding(s) of medium severity or higher; "
            "0 accepted by the owner, none reviewed by the AI, 0 blocking.") in out
    out = report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result="skipped")
    assert "## AI Security Gate: Blocked" in out
    assert "The AI review did not run for this change." in out
    assert "**2 blocking finding(s).** Resolve each one." in out
    assert "none reviewed by the AI, 2 blocking" in out
    assert out.count("not reviewed") == 2
    assert "requirements.txt" in out and "app/db.py" in out
    assert "Cleared by AI review" not in out
    assert "Model:" not in out and "- Scanners: " in out
    assert "<code></code>" not in out and "A change finding blocks" not in out
    # a failed baseline, skipped review
    b = {**load(BASELINE_PASS), "verdict": "ERROR", "error": "report unreadable"}
    out = report.render(None, baseline=b, review_result="skipped")
    assert "## AI Security Gate: Review incomplete" in out
    assert "**The scanner baseline did not finish:** report unreadable." in out


def test_incomplete_mode_lists_open_findings():
    for result in ("failure", "cancelled", "success", None):
        out = report.render(None, "o/r", baseline=load(BASELINE_BLOCK), review_result=result)
        assert "## AI Security Gate: Review incomplete" in out
        assert ("**The AI review did not finish.** The gate fails closed, so this change is "
                "blocked until a review completes.") in out
        assert "The AI review did not run" not in out
        assert "### Blocking findings" in out and out.count("not reviewed") == 2
        assert "CVE-2025-12345" in out and "python.sql.formatted-query" in out
    out = report.render(None)
    assert "Review incomplete" in out and "### " not in out


def test_ai_error_lists_baseline_findings():
    s = load(AI_BLOCK)
    s.update(verdict="ERROR", error="limit reached: triage findings", error_request_id=None,
             triage=[], scan=[])
    out = report.render(s, "o/r", baseline=load(BASELINE_BLOCK), review_result="failure")
    assert "**The review did not finish:** limit reached&#58; triage findings." in out
    assert "### Blocking findings" in out and out.count("not reviewed") == 2
    assert "none reviewed by the AI" in out
    assert "Model: <code>m-1</code>" in out
    # without a baseline the AI summary's own entries are used
    s2 = load(AI_BLOCK)
    s2.update(verdict="ERROR", error="x")
    assert "### Blocking findings" in report.render(s2)


def test_code_scan_rows_and_accepted():
    s = base_summary(verdict="BLOCK", scan=[
        code_entry(), code_entry(key="S2", ruling="suppressed", verdict=None, confidence=None,
                                 suppression={"reason": "r", "expires": "2027-01-01"}),
        code_entry(key="S3", ruling="cleared", verdict="false_positive", file="", line=0)])
    out = report.render(s, "o/r")
    assert "Code scan <code>example-sast</code>" in out
    assert "### Accepted risks" in out and "Cleared by AI review (1)" in out
    assert "Non-blocking findings (0)" in out
    assert "not reviewed" not in out
    assert "Deterministic scan: 3 finding(s)" in out
    assert "1 accepted by the owner, 1 cleared by the AI review, 1 blocking." in out


def test_hostile_scanner_strings():
    big = "Z" * 5000
    evil = "<script>`x`|a\n::error::x @someone ](http://x)"
    dep = scan(id="CVE-2025-1", package=evil, target=evil + big, verdict="unknown", file=evil,
               ruling="blocking")
    dep2 = scan(id="CVE-2025-2", target=evil + big, verdict="not_reachable", ruling="cleared")
    sup = scan(id="CVE-2025-3", target=evil + big, ruling="suppressed", verdict=None,
               suppression={"reason": evil, "expires": evil})
    code1 = code_entry(tool=evil + big, rule_id=evil + big, file=evil + big, severity=evil,
                       verdict=evil, confidence=evil, reason=evil + big)
    code2 = code_entry(tool=evil, rule_id=evil, file=evil, ruling="cleared", reason=evil + big)
    code3 = code_entry(tool=evil, rule_id=evil, file=evil + big, ruling="suppressed",
                       suppression={"reason": evil + big, "expires": evil})
    s = detailed(triage=[dep, dep2, sup], scan=[code1, code2, code3],
                 scanners=[{"name": evil + big, "version": evil}])
    out = report.render(s, "o/r")
    assert "<script" not in out and "`" not in out
    assert "@someone" not in out and "](http://x)" not in out
    assert not any(ln.startswith("::") for ln in out.splitlines())
    for m in re.findall(r"<code>(.*?)</code>", out):
        assert m.count("Z") <= 200
    for ln in out.splitlines():
        if ln.startswith("- Analysis"):
            assert ln.count("Z") <= 500
    assert "Z" * 501 not in out
    # every table row stays on one line
    assert all(ln.endswith("|") for ln in out.splitlines() if ln.startswith("|"))


def test_verdict_file_and_stdout(tmp_path):
    cases = [
        (["--summary", str(FIXTURE), "--review-result", "success"], "PASS", "Passed"),
        (["--summary", str(AI_BLOCK), "--baseline", str(BASELINE_BLOCK),
          "--review-result", "success"], "BLOCK", "Blocked"),
        (["--baseline", str(BASELINE_PASS), "--review-result", "skipped"], "PASS", "Passed"),
        (["--baseline", str(BASELINE_BLOCK), "--review-result", "skipped"], "BLOCK", "Blocked"),
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
        assert f"## AI Security Gate: {heading}" in r.stdout
    # an unwritable verdict file does not stop the markdown
    r = run_cli("--summary", str(FIXTURE), "--verdict-out", str(tmp_path / "no" / "v.txt"))
    assert r.returncode == 0 and r.stdout.startswith(report.MARKER)
    assert len(r.stderr.strip().splitlines()) == 1
