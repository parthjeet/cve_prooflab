import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "ci" / "sarif_min.py"
FIXTURE = ROOT / "ai-security-gate" / "selftest" / "fixtures" / "scan-triage" / "scan.sarif"
sys.path.insert(0, str(ROOT / "ai-security-gate"))

import scanner  # noqa: E402

SENTINEL = "SENTINEL-RULE-TEXT"


def run(tmp_path, doc, *flags, raw=None):
    src = tmp_path / "in.sarif"
    out = tmp_path / "out.sarif"
    src.write_text(raw if raw is not None else json.dumps(doc))
    p = subprocess.run([sys.executable, str(SCRIPT), *flags, str(src), str(out)],
                       capture_output=True, text=True)
    return p, src, out


def rule(rid, level=None, score=None, extra=True):
    r = {"id": rid}
    if level:
        r["defaultConfiguration"] = {"level": level, "rank": 5}
    if score is not None:
        r["properties"] = {"security-severity": score, "tags": [SENTINEL]}
    if extra:
        r.update({"name": SENTINEL, "shortDescription": {"text": SENTINEL},
                  "fullDescription": {"text": SENTINEL}, "help": {"text": SENTINEL},
                  "helpUri": SENTINEL})
    return r


def result(rid, uri="a.py", line=3, **kw):
    r = {"ruleId": rid, "message": {"text": "msg " + rid},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": SENTINEL},
                                             "region": {"startLine": line,
                                                        "snippet": {"text": SENTINEL}}}}],
         "fingerprints": {"x": SENTINEL}}
    r.update(kw)
    return r


def sarif(rules, results, **driver):
    d = {"name": "tool", "semanticVersion": "1.2.3", **driver, "rules": rules}
    return {"version": "2.1.0", "$schema": SENTINEL,
            "runs": [{"tool": {"driver": d}, "results": results,
                      "invocations": [{"executionSuccessful": True, "note": SENTINEL}],
                      "originalUriBaseIds": {"ROOT": {"uri": "file:///" + SENTINEL}}}]}


def findings(path):
    return scanner.load_sarif(str(path), "low")


def test_sentinel_dropped_with_drop_message(tmp_path):
    doc = sarif([rule("r1", "error", "8.0")], [result("r1")])
    doc["runs"][0]["results"][0]["message"]["text"] = SENTINEL
    p, _, out = run(tmp_path, doc, "--drop-message")
    assert p.returncode == 0
    text = out.read_text()
    assert SENTINEL not in text
    assert '"message"' not in text


def test_message_kept_without_flag_and_nothing_else(tmp_path):
    doc = sarif([rule("r1", "error", "8.0")], [result("r1")])
    p, _, out = run(tmp_path, doc)
    assert p.returncode == 0
    data = json.loads(out.read_text())
    assert data["runs"][0]["results"][0]["message"] == {"text": "msg r1"}
    assert SENTINEL not in out.read_text()
    for word in ("snippet", "fingerprints", "originalUriBaseIds", "invocations", "help"):
        assert word not in out.read_text()


CASES = {
    "score string": ([rule("r", "note", "9.5")], [result("r", ruleIndex=0)]),
    "result level": ([rule("r", "note")], [result("r", level="error", ruleIndex=0)]),
    "rule level by index": ([rule("x", "warning"), rule("r", "error")],
                            [result("r", ruleIndex=1)]),
    "rule level by id": ([rule("x", "warning"), rule("r", "error")], [result("r")]),
    "same id twice": ([rule("r", "error"), rule("r", "note")],
                      [result("r", line=1, ruleIndex=0), result("r", line=2, ruleIndex=1)]),
    "bad index falls back to id": ([rule("x", "note"), rule("r", "error")],
                                   [result("r", ruleIndex=99)]),
}


@pytest.mark.parametrize("name", sorted(CASES))
@pytest.mark.parametrize("drop", [False, True])
def test_loader_gives_equal_findings(tmp_path, name, drop):
    rules, results = CASES[name]
    doc = sarif(copy.deepcopy(rules), copy.deepcopy(results))
    p, src, out = run(tmp_path, doc, *(["--drop-message"] if drop else []))
    assert p.returncode == 0
    before, tools_before = findings(src)
    after, tools_after = findings(out)
    assert before and tools_before == tools_after
    if drop:
        before = [{**f, "message": ""} for f in before]
    assert before == after
    if name == "same id twice":
        assert [f["severity"] for f in after] == ["high", "low"]


def test_unused_rule_dropped_and_rule_id_form(tmp_path):
    results = [{"rule": {"id": "r2"}, "level": "error"}]
    doc = sarif([rule("r1", "error"), rule("r2", "warning")], results)
    p, src, out = run(tmp_path, doc)
    assert p.returncode == 0
    data = json.loads(out.read_text())
    run0 = data["runs"][0]
    assert [r["id"] for r in run0["tool"]["driver"]["rules"]] == ["r2"]
    assert run0["results"][0]["ruleId"] == "r2"
    assert run0["results"][0]["ruleIndex"] == 0
    assert "locations" not in run0["results"][0]
    assert findings(src) == findings(out)


def test_kind_pass_copied(tmp_path):
    doc = sarif([rule("r", "error")], [result("r", kind="pass")])
    p, src, out = run(tmp_path, doc)
    assert json.loads(out.read_text())["runs"][0]["results"][0]["kind"] == "pass"
    assert findings(src) == findings(out) == ([], [{"name": "tool", "version": "1.2.3"}])


def test_fixture_loads_equal(tmp_path):
    p, src, out = run(tmp_path, None, raw=FIXTURE.read_text())
    assert p.returncode == 0
    before, _ = findings(FIXTURE)
    after, _ = findings(out)
    assert len(before) == 2 and before == after


def test_bad_inputs_exit_2_and_write_nothing(tmp_path):
    good = sarif([rule("r", "error")], [result("r")])
    objects_runs = {"version": "2.1.0", "runs": {}}
    locs_object = copy.deepcopy(good)
    locs_object["runs"][0]["results"][0]["locations"] = {"a": 1}
    uri_object = copy.deepcopy(good)
    uri_object["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] = {"a": 1}
    for i, (doc, raw) in enumerate([(None, "{not json"), (objects_runs, None),
                                    (locs_object, None), (uri_object, None)]):
        sub = tmp_path / str(i)
        sub.mkdir()
        p, _, out = run(sub, doc, raw=raw)
        assert p.returncode == 2, i
        assert not out.exists(), i
        assert len(p.stderr.strip().splitlines()) == 1, i


def test_stdout_line_holds_counts(tmp_path):
    doc = sarif([rule("r1", "error"), rule("r2", "note"), rule("r3", "note")],
                [result("r1"), result("r1", line=9)])
    p, _, out = run(tmp_path, doc)
    assert p.stdout == "sarif_min: out.sarif runs=1 rules=3 results=2\n"
