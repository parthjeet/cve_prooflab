"""Offline tests for ci_verdict.py."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "showcase"))
import ci_verdict as cv  # noqa: E402

MODEL = "claude-mythos-5-2"


def call(outcome, returned=MODEL, task="R3"):
    return {"task_id": task, "model_requested": MODEL,
            "model_returned": returned, "outcome": outcome}


def run(tmp_path, capsys, calls, model=MODEL):
    path = tmp_path / "summary.json"
    path.write_text(json.dumps({"calls": calls}))
    code = cv.main(["ci_verdict.py", str(path), model])
    return code, capsys.readouterr().out.strip().splitlines()[-1]


def test_all_completed(tmp_path, capsys):
    code, line = run(tmp_path, capsys, [call("COMPLETED")] * 6)
    assert code == 0
    assert line == f"MODEL SHOWCASE: {MODEL} COMPLETED 6 of 6, REFUSED 0, OTHER 0"


def test_all_refused(tmp_path, capsys):
    code, line = run(tmp_path, capsys, [call("REFUSED")] * 6)
    assert code == 1
    assert line == f"MODEL SHOWCASE: {MODEL} COMPLETED 0 of 6, REFUSED 6, OTHER 0"


def test_mixed(tmp_path, capsys):
    calls = [call("COMPLETED")] * 4 + [call("REFUSED")] + [call("ERROR")]
    code, line = run(tmp_path, capsys, calls)
    assert code == 1
    assert line == f"MODEL SHOWCASE: {MODEL} COMPLETED 4 of 6, REFUSED 1, OTHER 1"


def test_truncated_counts_as_other(tmp_path, capsys):
    code, line = run(tmp_path, capsys, [call("COMPLETED"), call("TRUNCATED")])
    assert code == 1
    assert line == f"MODEL SHOWCASE: {MODEL} COMPLETED 1 of 2, REFUSED 0, OTHER 1"


def test_wrong_model_returned(tmp_path, capsys):
    calls = [call("COMPLETED")] * 5 + [call("COMPLETED", returned="claude-fable-5-2")]
    code, line = run(tmp_path, capsys, calls)
    assert code == 1
    assert "COMPLETED 6 of 6" in line


def test_empty_calls(tmp_path, capsys):
    code, line = run(tmp_path, capsys, [])
    assert code == 1
    assert line == f"MODEL SHOWCASE: {MODEL} COMPLETED 0 of 0, REFUSED 0, OTHER 0"


def test_missing_file(tmp_path, capsys):
    code = cv.main(["ci_verdict.py", str(tmp_path / "none.json"), MODEL])
    assert code == 2
    assert capsys.readouterr().out.startswith("MODEL SHOWCASE: ERROR ")


def test_unreadable_json(tmp_path, capsys):
    path = tmp_path / "summary.json"
    path.write_text("not json")
    assert cv.main(["ci_verdict.py", str(path), MODEL]) == 2
