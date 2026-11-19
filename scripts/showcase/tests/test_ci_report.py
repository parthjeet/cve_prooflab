"""Offline tests for ci_report.py."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "showcase"))
import ci_report as cr  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MODEL = "claude-mythos-5-2"
URL = "https://github.com/parthjeet/cve_prooflab/actions/runs/44411171620"
SENTINEL = "SENTINEL-DO-NOT-PRINT"


def call(outcome, task="R3", category=None, reason="end_turn"):
    return {"task_id": task, "repeat": 1, "model_requested": MODEL,
            "model_returned": MODEL, "outcome": outcome, "stop_reason": reason,
            "stop_category": category, "input_tokens": 10, "output_tokens": 5,
            "utc_date": "2026-11-19", "prompt_sha256": "ab" * 32,
            "output_sha256": SENTINEL, "system_sha256": SENTINEL}


def summary(calls):
    return {"calls": calls, "effort": "high", "max_tokens": 16000, "repeats": 3,
            "sdk_version": "2.10.0", "note": SENTINEL, "run_id": SENTINEL,
            "price_per_million_usd": {"input": 111.5}, "totals": {"cost_usd": 987.25}}


def test_all_completed():
    out = cr.render(summary([call("COMPLETED")] * 6))
    assert "COMPLETED 6 of 6, REFUSED 0, OTHER 0" in out
    assert f"## Model showcase: <code>{MODEL}</code>" in out
    assert "No generated test was run." in out


def test_all_refused_with_category():
    out = cr.render(summary([call("REFUSED", category="cyber", reason="refusal")] * 6))
    assert "COMPLETED 0 of 6, REFUSED 6, OTHER 0" in out
    assert "| <code>R3</code> | 6 | 0 | 6 | 0 | refusal x6 | cyber x6 |" in out


def test_mixed():
    calls = [call("COMPLETED")] * 4 + [call("REFUSED")] + [call("ERROR")]
    out = cr.render(summary(calls))
    assert "COMPLETED 4 of 6, REFUSED 1, OTHER 1" in out


def test_zero_calls():
    out = cr.render(summary([]))
    assert "COMPLETED 0 of 0, REFUSED 0, OTHER 0" in out
    assert "## Model showcase: no calls" in out


def test_models_disagree():
    other = call("COMPLETED")
    other["model_requested"] = "claude-fable-5-2"
    out = cr.render(summary([call("COMPLETED"), other]))
    assert "more than one model" in out


def test_hostile_stop_category():
    hostile = "<script>x</script>`|\n::error::boom @someone](http://x)" + "A" * 5000
    out = cr.render(summary([call("REFUSED", category=hostile)]))
    assert "<script" not in out
    assert "@someone" not in out
    assert "`" not in out
    assert not any(line.startswith("::") for line in out.splitlines())
    assert "A" * 201 not in out
    assert "&#60;script" in out


def test_hostile_other_fields():
    c = call("COMPLETED", task="R3\n::error::x")
    c["model_requested"] = c["model_returned"] = "<b>m</b>"
    s = summary([c])
    s["sdk_version"] = "<i>1</i>"
    out = cr.render(s)
    assert "<b>" not in out and "<i>" not in out
    assert not any(line.startswith("::") for line in out.splitlines())


def test_withheld_fields_absent():
    out = cr.render(summary([call("COMPLETED")]))
    for banned in (SENTINEL, "987.25", "111.5", "cost_usd", "price"):
        assert banned not in out


def test_run_url_checked():
    assert f"[Workflow run]({URL})" in cr.render(summary([]), URL)
    for bad in ("http://github.com/a/b/actions/runs/1",
                URL + ")[x](http://evil)", URL + "\n", "https://evil.example/a/b/actions/runs/1"):
        assert "Workflow run" not in cr.render(summary([]), bad)
    assert f"{URL}/attempts/2" in cr.render(summary([]), URL + "/attempts/2")


def test_marker_first_line():
    assert cr.render(summary([])).splitlines()[0] == "<!-- model-showcase-report -->"


def test_blank_line_after_summary_tag():
    lines = cr.render(summary([call("COMPLETED")])).splitlines()
    for i, line in enumerate(lines):
        if line.startswith("<summary>"):
            assert lines[i + 1] == ""


def test_forbidden_words():
    for calls in ([], [call("COMPLETED")] * 6,
                  [call("REFUSED", category="cyber", reason="refusal")] * 6):
        out = cr.render(summary(calls)).lower()
        assert "cannot" not in out and "requires" not in out


def test_row_cap():
    out = cr.render(summary([call("COMPLETED", task=f"T{i}") for i in range(80)]))
    assert "and 30 more; see the summary artifact" in out
    assert len(out) <= cr.MAX_CHARS


def test_missing_file(tmp_path, capsys):
    assert cr.main(["ci_report.py", str(tmp_path / "none.json")]) == 2
    cap = capsys.readouterr()
    assert cap.out == "" and len(cap.err.strip().splitlines()) == 1


def test_bad_inputs(tmp_path, capsys):
    for body in ("not json", "[]", '{"calls": 3}', '{}'):
        path = tmp_path / "s.json"
        path.write_text(body)
        assert cr.main(["ci_report.py", str(path)]) == 2
        assert capsys.readouterr().out == ""


def test_cli_ok(tmp_path, capsys):
    path = tmp_path / "s.json"
    path.write_text(json.dumps(summary([call("COMPLETED")])))
    assert cr.main(["ci_report.py", str(path), "--run-url", URL]) == 0
    assert capsys.readouterr().out.startswith("<!-- model-showcase-report -->\n")


def test_fixture_refused(capsys):
    assert cr.main(["ci_report.py", str(FIXTURES / "showcase-pr1.json")]) == 0
    out = capsys.readouterr().out
    assert "COMPLETED 0 of 6, REFUSED 6, OTHER 0" in out
    assert "claude-fable-5-2" in out


def test_fixture_completed(capsys):
    assert cr.main(["ci_report.py", str(FIXTURES / "showcase-pr2.json")]) == 0
    out = capsys.readouterr().out
    assert "COMPLETED 6 of 6, REFUSED 0, OTHER 0" in out
    assert "claude-mythos-5-2" in out
