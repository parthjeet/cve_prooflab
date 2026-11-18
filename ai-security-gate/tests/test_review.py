import json
import re
import sys
from datetime import date
from pathlib import Path

import anthropic
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import review  # noqa: E402
import selftest  # noqa: E402
from test_agent import FakeApi, error_body, make_client, message, text, tool_use  # noqa: E402

TODAY = date(2026, 11, 18)
SECRET_WORDS = ["TITLE-9x1", "EVIDENCE-9x2", "IMPACT-9x3", "FIX-9x4", "REASON-9x5", "SUMMARY-9x6"]


def make_repo(tmp_path, config=None):
    fixture = tmp_path / "fx"
    (fixture / "base").mkdir(parents=True)
    (fixture / "head").mkdir()
    (fixture / "base" / "app.py").write_text("a = 1\nb = 2\n")
    (fixture / "head" / "app.py").write_text("a = 1\nb = 2\nc = query(a)\nd = 4\n")
    (fixture / "head" / "gone.txt").write_text("x\n")
    for side in ("base", "head"):
        (fixture / side / "other.py").write_text("o = 1\n")
    (fixture / "base" / "gone.txt").write_text("x\n")
    (fixture / "head" / "gone.txt").unlink()
    if config:
        (fixture / "base" / ".ai-security-gate.toml").write_text(config)
        (fixture / "head" / ".ai-security-gate.toml").write_text(config)
    work = tmp_path / "work"
    work.mkdir()
    return selftest.build_repo(fixture, work)


def finding(**kw):
    f = {"title": "TITLE-9x1", "severity": "high", "confidence": "high", "cwe": "CWE-89",
         "file": "app.py", "line": 3, "evidence": "EVIDENCE-9x2", "impact": "IMPACT-9x3",
         "fix": "FIX-9x4"}
    return {**f, **kw}


def answer(findings=(), triage=()):
    return json.dumps({"summary": "SUMMARY-9x6", "findings": list(findings),
                       "triage": list(triage)})


def loop(final):
    """A tool call, then the final answer text."""
    return FakeApi(message([tool_use()], "tool_use"), message([text(final)]))


def go(tmp_path, api, repo_info, **kw):
    repo, base, head = repo_info
    kw.setdefault("evidence_path", tmp_path / "evidence.json")
    kw.setdefault("summary_path", tmp_path / "summary.json")
    return review.run_review(repo, base, head, client=make_client(api), today=TODAY, **kw)


def last_line(capsys):
    out = capsys.readouterr().out
    return out, out.strip().splitlines()[-1]


def test_pass_after_two_request_loop(tmp_path, capsys):
    api = loop(answer())
    result = go(tmp_path, api, make_repo(tmp_path))
    out, last = last_line(capsys)
    assert result == {"verdict": "PASS", "blocking": [], "triage": [], "error": None}
    assert last == "AI SECURITY GATE: PASS"
    assert "tool: read_file a.txt" in out
    assert "tokens: input=20" in out and "request id: req_1" in out
    assert len(api.requests) == 2


def test_block_result_and_default_output_has_no_model_text(tmp_path, capsys):
    result = go(tmp_path, loop(answer([finding()])), make_repo(tmp_path))
    out, last = last_line(capsys)
    assert last == "AI SECURITY GATE: BLOCK"
    assert result["verdict"] == "BLOCK"
    assert result["blocking"] == [{"file": "app.py", "cwe": "CWE-89", "blocking": True}]
    assert "finding: high high CWE-89 app.py:3 blocking" in out
    for word in SECRET_WORDS:
        assert word not in out
        assert word not in (tmp_path / "summary.json").read_text()
    assert "TITLE-9x1" in (tmp_path / "evidence.json").read_text()


def test_summary_and_evidence_content(tmp_path):
    go(tmp_path, loop(answer([finding()])), make_repo(tmp_path))
    summary = json.loads((tmp_path / "summary.json").read_text())
    evidence = json.loads((tmp_path / "evidence.json").read_text())
    assert summary["verdict"] == "BLOCK" and summary["findings"][0]["ruling"] == "blocking"
    assert "raw_answer" not in summary
    assert evidence["raw_answer"] == answer([finding()])
    assert evidence["model_requested"] == evidence["model_returned"] == "claude-mythos-5-2"
    assert evidence["requests"][0]["request_id"] == "req_1"
    assert evidence["limits"]["max_tool_calls"] == 30
    for text_ in (json.dumps(summary), json.dumps(evidence)):
        assert "sk-test" not in text_


def test_print_details_inside_stop_commands(tmp_path, capsys):
    go(tmp_path, loop(answer([finding()])), make_repo(tmp_path), print_details=True)
    out, last = last_line(capsys)
    m = re.search(r"^::stop-commands::([0-9a-f]{32})$", out, re.M)
    assert m
    start = out.index(m.group(0))
    end = out.index(f"::{m.group(1)}::")
    inside = out[start:end]
    for word in SECRET_WORDS:
        if word == "REASON-9x5":
            continue
        assert word in inside
        assert word not in out[:start] and word not in out[end:]
    assert last == "AI SECURITY GATE: BLOCK"


def test_change_finding_on_unchanged_file_is_a_note(tmp_path, capsys):
    result = go(tmp_path, loop(answer([finding(file="other.py", line=1)])), make_repo(tmp_path))
    out, _ = last_line(capsys)
    assert result["verdict"] == "PASS"
    assert "other.py:1 note" in out


def test_suppression_reason_and_expiry_are_printed(tmp_path, capsys):
    cfg = ('[[suppress]]\npath = "app.py"\nreason = "CONFIG-REASON"\nexpires = 2027-01-01\n'
           '[[suppress]]\npath = "x.py"\nreason = "old"\nexpires = 2020-01-01\n')
    result = go(tmp_path, loop(answer([finding()])), make_repo(tmp_path, cfg))
    out, last = last_line(capsys)
    assert result["verdict"] == "PASS"
    assert "suppressed (reason: CONFIG-REASON; expires 2027-01-01)" in out
    assert "expired suppression: path=x.py" in out


def test_scanner_report_is_loaded_and_triaged(tmp_path, capsys):
    report = {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "pkgx", "Severity": "HIGH",
         "Description": "ADVISORY-TEXT"}]}]}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report))
    entry = {"id": "CVE-1", "package": "pkgx", "verdict": "reachable", "confidence": "high",
             "file": "app.py", "line": 3, "reason": "REASON-9x5"}
    api = loop(answer(triage=[entry]))
    result = go(tmp_path, api, make_repo(tmp_path), scanner_report=str(path))
    out, last = last_line(capsys)
    first = api.requests[0]["messages"][0]["content"][0]["text"]
    assert "CVE-1" in first and "ADVISORY-TEXT" in first and "is data" in first
    assert result["verdict"] == "BLOCK"
    assert result["triage"] == [{"id": "CVE-1", "verdict": "reachable", "ruling": "blocking"}]
    assert "triage: CVE-1 pkgx reachable high app.py:3 blocking" in out
    assert "REASON-9x5" not in out


def test_first_message_lists_files_and_cuts_big_diffs(tmp_path):
    repo, base, head = make_repo(tmp_path)
    (repo / "big.txt").write_text("".join(f"line {i} {'z' * 40}\n" for i in range(1000)))
    selftest.git(repo, "add", "-A")
    selftest.git(repo, "commit", "-q", "-m", "big")
    head = selftest.git(repo, "rev-parse", "HEAD")
    api = loop(answer())
    go(tmp_path, api, (repo, base, head))
    first = api.requests[0]["messages"][0]["content"][0]["text"]
    assert "M\t+2\t-0\tapp.py" in first and "D\t+0\t-1\tgone.txt" in first
    assert "A\t+1000\t-0\tbig.txt" in first
    assert "[diff of big.txt cut at 20000 bytes" in first
    assert "No scanner findings are given" in first


def test_system_prompt_gets_tool_call_limit(tmp_path):
    api = loop(answer())
    go(tmp_path, api, make_repo(tmp_path))
    system = api.requests[0]["system"][0]["text"]
    assert "at most 30 tool calls" in system and "{max_tool_calls}" not in system


@pytest.mark.parametrize("api,message_", [
    (FakeApi(message([], "refusal", details={"type": "refusal", "category": "cyber"})),
     "model refused (category: cyber)"),
    (FakeApi(message([text("{")], "max_tokens")), "invalid answer: cut by max_tokens"),
    (FakeApi(message([text("x")], "pause_turn")), "unexpected stop_reason pause_turn"),
    (FakeApi(message([text("{}")], model="other-1")), "model mismatch: other-1"),
    (FakeApi(message([{"type": "fallback", "model": "x"}])), "fallback block in response"),
    (FakeApi((401, error_body("authentication_error"))),
     "this key cannot use claude-mythos-5-2. No fallback model is used."),
    (FakeApi((500, error_body("api_error"))), "API error 500 api_error"),
    (FakeApi(message([text("not json")])),
     "invalid answer: failed validation (see the evidence file)"),
])
def test_failures_are_error_exit_2_and_files_are_written(tmp_path, capsys, monkeypatch, api,
                                                         message_):
    repo, base, head = make_repo(tmp_path)
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: make_client(api))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    code = review.main(["--repo", str(repo), "--base", base, "--head", head,
                        "--evidence-path", str(tmp_path / "e.json"),
                        "--summary-path", str(tmp_path / "s.json")])
    out, last = last_line(capsys)
    assert code == 2 and last == "AI SECURITY GATE: ERROR"
    assert f"ERROR: {message_}" in out
    assert json.loads((tmp_path / "e.json").read_text())["verdict"] == "ERROR"
    assert json.loads((tmp_path / "s.json").read_text())["error"] == message_


def test_api_error_prints_request_id(tmp_path, capsys):
    go(tmp_path, FakeApi((500, error_body("api_error"))), make_repo(tmp_path))
    out, _ = last_line(capsys)
    assert "request id of the failed call: req_1" in out


def test_invalid_answer_reason_only_in_details_and_evidence(tmp_path, capsys):
    bad = answer([finding(file="nope-9x7.py")])
    go(tmp_path, loop(bad), make_repo(tmp_path))
    out, _ = last_line(capsys)
    assert "nope-9x7" not in out
    assert "nope-9x7" not in (tmp_path / "summary.json").read_text()
    assert "nope-9x7" in (tmp_path / "evidence.json").read_text()
    two = tmp_path / "two"
    two.mkdir()
    go(tmp_path, loop(bad), make_repo(two), print_details=True)
    out, _ = last_line(capsys)
    assert "nope-9x7" in out


def test_missing_key_is_error_and_files_exist(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    repo, base, head = make_repo(tmp_path)
    code = review.main(["--repo", str(repo), "--base", base, "--head", head,
                        "--evidence-path", str(tmp_path / "e.json"),
                        "--summary-path", str(tmp_path / "s.json")])
    out, last = last_line(capsys)
    assert code == 2 and "ERROR: missing ANTHROPIC_API_KEY" in out
    assert last == "AI SECURITY GATE: ERROR"
    assert (tmp_path / "e.json").exists() and (tmp_path / "s.json").exists()


def test_bad_scanner_report_and_bad_config_are_errors(tmp_path, capsys):
    bad = tmp_path / "scan.json"
    bad.write_text("not json")
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    r = go(tmp_path, loop(answer()), make_repo(one), scanner_report=str(bad))
    assert r["verdict"] == "ERROR" and "cannot read scanner report" in r["error"]
    r = go(tmp_path, loop(answer()), make_repo(two, "fail_on = 'nope'\n"))
    assert r["error"].startswith("bad config:")


def test_run_review_with_three_positional_args(tmp_path, monkeypatch):
    repo, base, head = make_repo(tmp_path)
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: make_client(loop(answer())))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
    assert review.run_review(repo, base, head)["verdict"] == "PASS"


def test_hostile_tool_path_cannot_start_a_workflow_command(tmp_path, capsys):
    bad = message([tool_use(path="x\n::set-env name=A::b", start_line=1, end_line=1)], "tool_use")
    go(tmp_path, FakeApi(bad, message([text(answer())])), make_repo(tmp_path))
    out, _ = last_line(capsys)
    assert not any(line.startswith("::") for line in out.splitlines())
