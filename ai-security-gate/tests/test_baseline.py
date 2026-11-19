import json
import subprocess
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import baseline  # noqa: E402
import selftest  # noqa: E402

GATE_DIR = Path(__file__).resolve().parent.parent


def make_repo(tmp_path, config=None):
    fixture = tmp_path / "fx"
    for side in ("base", "head"):
        (fixture / side).mkdir(parents=True)
        (fixture / side / "app.py").write_text("a = 1\n" if side == "base" else "a = 2\n")
        if config:
            (fixture / side / ".ai-security-gate.toml").write_text(config)
    work = tmp_path / "work"
    work.mkdir()
    return selftest.build_repo(fixture, work)


def sarif_file(tmp_path, rules=("rule.x",), message="MESSAGE-7q1", level="error"):
    results = [{"ruleId": r, "level": level, "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"},
                                                    "region": {"startLine": 1}}}]}
               for r in rules]
    path = tmp_path / "s.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "example-sast", "version": "1.0"}}, "results": results}]}))
    return str(path)


def dep_file(tmp_path, target="req.txt"):
    path = tmp_path / "dep.json"
    path.write_text(json.dumps({"SchemaVersion": 2, "Results": [
        {"Class": "lang-pkgs", "Target": target, "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "pkgx", "InstalledVersion": "1.0",
             "FixedVersion": "1.1", "Severity": "HIGH", "Title": "TITLE-7q2",
             "Description": "DESC-7q3"}]}]}))
    return str(path)


def run(tmp_path, repo_info, *extra):
    repo, base, head = repo_info
    out = tmp_path / "out.json"
    code = baseline.main(["--repo", str(repo), "--base", base, "--head", head,
                          "--summary-path", str(out), *extra])
    return code, json.loads(out.read_text())


def test_pass_with_no_reports(tmp_path, capsys):
    code, summary = run(tmp_path, make_repo(tmp_path))
    assert code == 0 and summary["verdict"] == "PASS" and summary["kind"] == "baseline"
    assert capsys.readouterr().out.strip().splitlines() == ["SECURITY BASELINE: PASS"]


def test_block_and_summary_shape(tmp_path, capsys):
    code, summary = run(tmp_path, make_repo(tmp_path), "--scanner-report", dep_file(tmp_path),
                        "--sarif", sarif_file(tmp_path))
    out = capsys.readouterr().out.strip().splitlines()
    assert code == 1 and out[-1] == "SECURITY BASELINE: BLOCK"
    assert "scan: dependency CVE-1 high req.txt blocking" in out
    assert "scan: example-sast rule.x high app.py:1 blocking" in out
    assert set(summary) == {"kind", "verdict", "error", "base", "head", "notice", "limits",
                            "scanners", "triage", "scan", "expired_suppressions"}
    assert summary["limits"] == {"triage_min_severity": "high"}
    assert summary["scanners"] == [{"name": "example-sast", "version": "1.0"}]
    t = summary["triage"][0]
    assert t["installed_version"] == "1.0" and t["fixed_version"] == "1.1"
    assert t["verdict"] is None and t["confidence"] is None and t["ruling"] == "blocking"
    s = summary["scan"][0]
    assert s["key"] == "S1" and s["verdict"] is None and s["tool"] == "example-sast"


def test_accepted_findings_pass_and_are_suppressed(tmp_path, capsys):
    cfg = ('[[suppress]]\npath = "req.txt"\nreason = "R"\nexpires = 2999-01-01\n'
           '[[suppress]]\nid = "rule.x"\nreason = "R2"\nexpires = 2999-01-01\n')
    code, summary = run(tmp_path, make_repo(tmp_path, cfg),
                        "--scanner-report", dep_file(tmp_path), "--sarif", sarif_file(tmp_path))
    out = capsys.readouterr().out
    assert code == 0 and "SECURITY BASELINE: PASS" in out
    assert summary["triage"][0]["ruling"] == "suppressed"
    assert summary["scan"][0]["ruling"] == "suppressed" and summary["scan"][0]["key"] is None
    assert summary["scan"][0]["suppression"]["reason"] == "R2"


def test_below_threshold_passes(tmp_path):
    code, _ = run(tmp_path, make_repo(tmp_path), "--sarif",
                  sarif_file(tmp_path, level="note"))
    assert code == 0


def test_error_exit_on_bad_report_and_bad_config(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    code, summary = run(tmp_path, make_repo(one), "--sarif", str(bad))
    out = capsys.readouterr().out.strip().splitlines()
    assert code == 2 and summary["verdict"] == "ERROR" and out[-1] == "SECURITY BASELINE: ERROR"
    assert "cannot read SARIF report" in summary["error"]
    code, summary = run(tmp_path, make_repo(two, "fail_on = 'nope'\n"))
    assert code == 2 and summary["error"].startswith("bad config:")


def test_scanner_text_never_printed_or_written(tmp_path, capsys):
    run(tmp_path, make_repo(tmp_path), "--scanner-report", dep_file(tmp_path),
        "--sarif", sarif_file(tmp_path))
    out = capsys.readouterr().out
    written = (tmp_path / "out.json").read_text()
    for word in ("MESSAGE-7q1", "TITLE-7q2", "DESC-7q3"):
        assert word not in out and word not in written


def test_hostile_values_are_escaped_in_output(tmp_path, capsys):
    path = sarif_file(tmp_path, rules=("x\n::set-env name=A::b",))
    run(tmp_path, make_repo(tmp_path), "--sarif", path)
    out = capsys.readouterr().out
    assert not any(line.startswith("::") for line in out.splitlines())


def test_runs_without_anthropic(tmp_path):
    repo, base, head = make_repo(tmp_path)
    code = ("import sys\nsys.modules['anthropic'] = None\n"
            f"sys.path.insert(0, {str(GATE_DIR)!r})\nimport baseline\n"
            f"sys.exit(baseline.main(['--repo', {str(repo)!r}, '--base', {base!r}, "
            f"'--head', {head!r}, '--summary-path', {str(tmp_path / 'o.json')!r}]))\n")
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "SECURITY BASELINE: PASS"


def test_entry_helpers_are_shared_with_review():
    import review
    assert review.baseline is baseline and review.safe is baseline.safe
