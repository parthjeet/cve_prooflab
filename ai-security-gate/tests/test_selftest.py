import json
import subprocess
import sys
from pathlib import Path

import pytest

GATE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GATE_DIR))

import review  # noqa: E402
import scanner  # noqa: E402
import selftest  # noqa: E402

FIXTURES = GATE_DIR / "selftest" / "fixtures"
NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())


def git_out(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout


def tree(root):
    return {str(p.relative_to(root)): p.read_bytes()
            for p in Path(root).rglob("*") if p.is_file() and ".git" not in p.parts}


def expected_of(name):
    return json.loads((FIXTURES / name / "expected.json").read_text())


def fake_expected(repo, base, head, scanner_report=None, sarif_reports=()):
    name = Path(repo).name
    for n in NAMES:
        if name.startswith(n + "-"):
            exp = expected_of(n)
    blocking = [{"file": r["file"], "cwe": r["cwe_any"][0], "blocking": True}
                for r in exp["require"]]
    triage = [{"id": i, "verdict": v,
               "ruling": "blocking" if v == "reachable" else "note"}
              for i, v in exp.get("triage", {}).items()]
    scan = []
    for key, want in exp.get("scan", {}).items():
        file, _, line = key.rpartition(":")
        scan.append({"file": file, "line": int(line), **want})
    return {"verdict": exp["verdict"], "blocking": blocking, "triage": triage, "scan": scan}


def test_fixture_names():
    assert NAMES == ["injected-instruction", "scan-triage", "sql-injection", "sql-injection-fixed",
                     "triage-not-reachable", "triage-reachable"]


@pytest.mark.parametrize("name", NAMES)
def test_expected_json_shape(name):
    exp = expected_of(name)
    assert exp["verdict"] in ("PASS", "BLOCK")
    for req in exp["require"]:
        assert set(req) == {"file", "cwe_any", "blocking"}


@pytest.mark.parametrize("name", NAMES)
def test_build_repo_diff(name, tmp_path):
    repo, base, head = selftest.build_repo(FIXTURES / name, tmp_path)
    out = git_out(repo, "diff", f"{base}...{head}", "--name-only")
    assert out.split() == ["app.py"]
    assert tree(repo) == tree(FIXTURES / name / "head")


def test_build_repo_deletes_and_adds(tmp_path):
    fx = tmp_path / "fx"
    (fx / "base").mkdir(parents=True)
    (fx / "head" / "sub").mkdir(parents=True)
    (fx / "base" / "keep.py").write_text("a = 1\n")
    (fx / "base" / "gone.py").write_text("b = 2\n")
    (fx / "head" / "keep.py").write_text("a = 2\n")
    (fx / "head" / "sub" / "new.py").write_text("c = 3\n")
    work = tmp_path / "work"
    work.mkdir()
    repo, base, head = selftest.build_repo(fx, work)
    assert tree(repo) == tree(fx / "head")
    assert not (repo / "gone.py").exists()
    names = set(git_out(repo, "diff", f"{base}...{head}", "--name-only").split())
    assert names == {"keep.py", "gone.py", "sub/new.py"}


EXP = {"verdict": "BLOCK",
       "require": [{"file": "app.py", "cwe_any": ["CWE-89"], "blocking": True}]}
FINDING = {"file": "app.py", "cwe": "CWE-89", "blocking": True}


def test_check_ok():
    assert selftest.check(EXP, {"verdict": "BLOCK", "blocking": [FINDING]})[0]


def test_check_verdict_mismatch():
    ok, reason = selftest.check(EXP, {"verdict": "PASS", "blocking": []})
    assert not ok and "PASS" in reason


def test_check_wrong_cwe():
    wrong = dict(FINDING, cwe="CWE-79")
    assert not selftest.check(EXP, {"verdict": "BLOCK", "blocking": [wrong]})[0]


def test_check_wrong_file():
    wrong = dict(FINDING, file="other.py")
    assert not selftest.check(EXP, {"verdict": "BLOCK", "blocking": [wrong]})[0]


def test_check_empty_blocking():
    assert not selftest.check(EXP, {"verdict": "BLOCK", "blocking": []})[0]


def test_check_error_never_ok():
    assert not selftest.check({"verdict": "PASS", "require": []},
                              {"verdict": "ERROR", "blocking": []})[0]
    assert not selftest.check({"verdict": "ERROR", "require": []},
                              {"verdict": "ERROR", "blocking": []})[0]


def test_run_all_match(tmp_path, capsys):
    code = selftest.run(FIXTURES, fake_expected, tmp_path)
    lines = capsys.readouterr().out.splitlines()
    assert code == 0
    assert lines == [f"{n}: MATCH" for n in NAMES] + ["AI GATE SELF-TEST: PASS"]


def test_run_exception_is_mismatch(tmp_path, capsys):
    def fake(repo, base, head, report, sarif_reports=()):
        if Path(repo).name.startswith("sql-injection-fixed-"):
            raise RuntimeError("boom")
        return fake_expected(repo, base, head, report, sarif_reports)

    code = selftest.run(FIXTURES, fake, tmp_path)
    lines = capsys.readouterr().out.splitlines()
    assert code == 1
    assert any(l.startswith("sql-injection-fixed: MISMATCH") for l in lines)
    assert lines[-1] == "AI GATE SELF-TEST: FAIL"


def test_run_harness_error(tmp_path, capsys):
    bad = tmp_path / "fixtures" / "broken"
    bad.mkdir(parents=True)
    code = selftest.run(tmp_path / "fixtures", fake_expected, tmp_path)
    assert code == 2
    assert capsys.readouterr().out.splitlines()[-1] == "AI GATE SELF-TEST: ERROR"


TRIAGE_EXP = {"verdict": "BLOCK", "require": [],
              "triage": {"CVE-2022-22817": "reachable"}}


def triage_result(verdict="reachable", ruling="blocking", vuln_id="CVE-2022-22817",
                  top="BLOCK"):
    return {"verdict": top, "blocking": [],
            "triage": [{"id": vuln_id, "verdict": verdict, "ruling": ruling}]}


def test_check_triage_match():
    assert selftest.check(TRIAGE_EXP, triage_result())[0]


def test_check_triage_wrong_verdict():
    ok, reason = selftest.check(TRIAGE_EXP, triage_result(verdict="unknown"))
    assert not ok and "CVE-2022-22817" in reason


def test_check_triage_missing_id():
    ok, reason = selftest.check(TRIAGE_EXP, triage_result(vuln_id="CVE-2000-0001"))
    assert not ok and "CVE-2022-22817" in reason


def test_check_triage_reachable_needs_blocking():
    ok, reason = selftest.check(TRIAGE_EXP, triage_result(ruling="note"))
    assert not ok and "CVE-2022-22817" in reason


def test_check_triage_not_reachable_exact():
    exp = {"verdict": "PASS", "require": [], "triage": {"CVE-2023-44271": "not_reachable"}}
    assert selftest.check(exp, triage_result("not_reachable", "note", "CVE-2023-44271", "PASS"))[0]
    assert not selftest.check(exp, triage_result("unknown", "note", "CVE-2023-44271", "PASS"))[0]


def test_check_triage_duplicate_entry():
    result = triage_result()
    result["triage"].append(dict(result["triage"][0]))
    assert not selftest.check(TRIAGE_EXP, result)[0]


TRIAGE_NAMES = ["triage-not-reachable", "triage-reachable"]


@pytest.mark.parametrize("name", TRIAGE_NAMES)
def test_triage_scanner_report_ids(name):
    found = scanner.load(FIXTURES / name / "scanner-report.json", "high")
    assert len(found) == 2
    assert {f["VulnerabilityID"] for f in found} == set(expected_of(name)["triage"])


def test_triage_scanner_reports_identical():
    a, b = (FIXTURES / n / "scanner-report.json" for n in TRIAGE_NAMES)
    assert a.read_bytes() == b.read_bytes()


@pytest.mark.parametrize("name", TRIAGE_NAMES)
def test_triage_requirements_identical(name):
    base = (FIXTURES / name / "base" / "requirements.txt").read_bytes()
    assert base == (FIXTURES / name / "head" / "requirements.txt").read_bytes()


def install_fake_review(monkeypatch, calls):
    def fake(repo, base, head, scanner_report=None, sarif_reports=(), **kwargs):
        calls.append(kwargs)
        ev = kwargs.get("evidence_path")
        if ev:
            Path(ev).write_text(json.dumps({"totals": {
                "total_input_tokens": 100, "output_tokens": 10, "requests": 2}}))
        return fake_expected(repo, base, head, scanner_report, sarif_reports)

    monkeypatch.setattr(review, "run_review", fake)


def test_main_evidence_dir_paths(tmp_path, monkeypatch, capsys):
    calls = []
    install_fake_review(monkeypatch, calls)
    out_dir = tmp_path / "out" / "nested"
    code = selftest.main(["--evidence-dir", str(out_dir)])
    lines = capsys.readouterr().out.splitlines()
    assert code == 0
    assert len(calls) == 6
    assert sorted(Path(c["evidence_path"]).name for c in calls) == \
        sorted(f"{n}-evidence.json" for n in NAMES)
    assert sorted(Path(c["summary_path"]).name for c in calls) == \
        sorted(f"{n}-summary.json" for n in NAMES)
    assert all(Path(c["evidence_path"]).parent == out_dir for c in calls)
    assert lines[-1] == "self-test tokens: input=600 output=60 requests=12"


def test_main_token_line_missing_totals(tmp_path, monkeypatch, capsys):
    def fake(repo, base, head, scanner_report=None, sarif_reports=(), **kwargs):
        Path(kwargs["evidence_path"]).write_text(json.dumps({"totals": None}))
        return fake_expected(repo, base, head, scanner_report, sarif_reports)

    monkeypatch.setattr(review, "run_review", fake)
    selftest.main(["--evidence-dir", str(tmp_path)])
    assert capsys.readouterr().out.splitlines()[-1] == \
        "self-test tokens: input=0 output=0 requests=0"


def test_main_without_evidence_dir(monkeypatch, capsys):
    calls = []
    install_fake_review(monkeypatch, calls)
    code = selftest.main([])
    out = capsys.readouterr().out
    assert code == 0
    assert calls == [{}] * 6
    assert "self-test tokens" not in out


SCAN_DIR = FIXTURES / "scan-triage"


def test_scan_triage_db_identical():
    assert (SCAN_DIR / "base" / "db.py").read_bytes() == (SCAN_DIR / "head" / "db.py").read_bytes()


def test_scan_triage_sarif_lines_hold_execute():
    lines = (SCAN_DIR / "head" / "db.py").read_text().splitlines()
    keys = expected_of("scan-triage")["scan"]
    assert len(keys) == 2
    for key in keys:
        file, _, line = key.rpartition(":")
        assert file == "db.py"
        assert "execute(" in lines[int(line) - 1]


def test_scan_triage_load_sarif():
    found, tools = scanner.load_sarif(SCAN_DIR / "scan.sarif", "high")
    assert len(found) == 2
    assert tools == [{"name": "example-sast", "version": "1.0.0"}]
    assert {f["rule_id"] for f in found} == {"python.sql.formatted-query"}
    assert {f"{f['file']}:{f['line']}" for f in found} == set(expected_of("scan-triage")["scan"])


def test_run_passes_sarif_reports(tmp_path):
    seen = {}

    def fake(repo, base, head, report, sarif_reports=()):
        seen[Path(repo).name.rsplit("-", 1)[0]] = sarif_reports
        return fake_expected(repo, base, head, report, sarif_reports)

    assert selftest.run(FIXTURES, fake, tmp_path) == 0
    assert seen["scan-triage"] == (str(SCAN_DIR / "scan.sarif"),)
    assert seen["sql-injection"] == ()


SCAN_EXP = {"verdict": "BLOCK", "require": [],
            "scan": {"db.py:16": {"verdict": "true_positive", "ruling": "blocking"}}}


def scan_result(verdict="true_positive", ruling="blocking", file="db.py", line=16):
    return {"verdict": "BLOCK", "blocking": [],
            "scan": [{"file": file, "line": line, "verdict": verdict, "ruling": ruling}]}


def test_check_scan_match():
    assert selftest.check(SCAN_EXP, scan_result())[0]


def test_check_scan_wrong_verdict():
    ok, reason = selftest.check(SCAN_EXP, scan_result(verdict="false_positive"))
    assert not ok and "db.py:16" in reason


def test_check_scan_wrong_ruling():
    ok, reason = selftest.check(SCAN_EXP, scan_result(ruling="cleared"))
    assert not ok and "db.py:16" in reason


def test_check_scan_missing_entry():
    ok, reason = selftest.check(SCAN_EXP, scan_result(line=99))
    assert not ok and "db.py:16" in reason
    assert not selftest.check(SCAN_EXP, {"verdict": "BLOCK", "blocking": []})[0]
