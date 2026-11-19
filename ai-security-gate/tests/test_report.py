import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import report  # noqa: E402

HERE = Path(__file__).resolve().parent
REPORT_PY = HERE.parent / "report.py"
FIXTURE = HERE / "fixtures" / "report" / "pass-summary.json"
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


def test_real_pass_summary():
    out = report.render(real(), "o/r", None)
    assert "## AI security gate: PASS" in out
    assert "### Blocking" not in out
    sup = out.split("### Suppressed")[1].split("<details>")[0]
    rows = [ln for ln in sup.splitlines() if ln.startswith("| ") and "CVE-" in ln]
    assert len(rows) == 1
    assert "CVE-2026-48817" in rows[0] and "app/app.py&#58;23" in rows[0]
    assert "Deliberate target" in rows[0] and "2027-05-18" in rows[0]
    assert "Not blocking (10)" in out
    assert "45105" in out and "2867" in out


def test_block_order():
    s = base_summary(verdict="BLOCK", findings=[change()], triage=[scan(id="CVE-2025-99999")])
    s["triage"].append(scan(id="CVE-2025-11111", ruling="suppressed",
                            suppression={"reason": "r", "expires": "2027-01-01"}))
    out = report.render(s, "o/r")
    b, sp, d = out.index("### Blocking"), out.index("### Suppressed"), out.index("<details>")
    assert b < sp < d
    blocking = out[b:sp]
    assert "CWE-22" in blocking and "CVE-2025-99999" in blocking
    assert "2 item(s) block this change" in out


def test_error():
    s = base_summary(verdict="ERROR", error="boom happened", error_request_id="req_abc123")
    out = report.render(s)
    assert "The review did not finish: boom happened." in out
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
                                  ruling="note") for i in range(80)])
    out = report.render(s)
    notes = out.split("Not blocking (80)")[1].split("</details>")[0]
    assert sum(1 for ln in notes.splitlines() if ln.startswith("| ") and "CVE-" in ln) == 50
    assert "and 30 more; see the summary artifact" in out
    huge = base_summary(findings=[change(ruling="blocking", file="f" * 150 + str(i))
                                  for i in range(1000)],
                        triage=[scan(ruling="note", id="X" * 190 + str(i)) for i in range(1000)],
                        verdict="BLOCK")
    assert len(report.render(huge, "o/r")) <= 60000
    giant = base_summary(totals={f"k{i}": i for i in range(20000)})
    out = report.render(giant)
    assert len(out) <= 60000 and "cut at 60000" in out


def test_warnings():
    out = report.render(base_summary())
    assert "config came from the change" not in out and "differs" not in out
    assert "config came from the change under review" in report.render(base_summary(notice="x"))
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


def test_cli_errors(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    lst = tmp_path / "list.json"
    lst.write_text("[1]")
    noverdict = tmp_path / "nv.json"
    noverdict.write_text("{}")
    for p in (tmp_path / "missing.json", bad, lst, noverdict):
        r = run_cli(str(p))
        assert r.returncode == 2 and r.stdout == ""
        assert len(r.stderr.strip().splitlines()) == 1


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
