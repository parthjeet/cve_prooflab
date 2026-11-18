"""Offline tests for compare_models.py. No network: the client uses a mock
transport from httpx2 (anthropic 2.10.0 builds on httpx2, not httpx). Prompt
files and expected results are temporary copies, not the frozen ones."""
import json
import re
import sys
from datetime import date
from pathlib import Path

import anthropic
import httpx2
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import compare_models as cm  # noqa: E402

FAKE_KEY = "sk-test-not-real"
MYTHOS, FABLE = "claude-mythos-5-2", "claude-fable-5-2"
SYSTEM_TEXT = "system text for tests\n"
R1_IDS = ["CVE-A", "CVE-B"]
R2_IDS = ["CVE-C", "CVE-D", "CVE-E"]
R5_CVES = ["CVE-X", "CVE-Y"]
EXPECTED = {
    "R1": {"ids": R1_IDS},
    "R2": {"ids": R2_IDS},
    "R3": {}, "R4": {},
    "R5": {"cves": R5_CVES},
}
MEANING = "MEANING: a pass means the file is served, a fail means it is not."
PY_GOOD = "```python\ndef test_x():\n    assert True\n```\n" + MEANING


def good_answer(task):
    if task == "R1":
        return json.dumps({"ranking": [
            {"id": i, "verdict": "affected", "reason": "r"} for i in R1_IDS]})
    if task == "R2":
        return "```json\n" + json.dumps({"advisories": [
            {"id": i, "reachable": "no", "reason": "r", "check": "c"}
            for i in R2_IDS]}) + "\n```"
    if task in ("R3", "R4"):
        return PY_GOOD
    return json.dumps({
        "incidents": [{"line": 4, "cve": "CVE-X", "succeeded": True}],
        "rules": [{"cve": c, "regex": r"\.\./x"} for c in R5_CVES]})


def check(task, text):
    return cm.CHECKS[task](text, EXPECTED[task])[0]


@pytest.fixture(autouse=True)
def isolate(monkeypatch):
    monkeypatch.setattr(cm, "RETRY_DELAYS", (0, 0, 0))
    monkeypatch.setattr(cm, "utc_today", lambda: date(2026, 11, 18))


@pytest.fixture
def prompts_dir(tmp_path):
    d = tmp_path / "prompts"
    d.mkdir()
    (d / "system.md").write_text(SYSTEM_TEXT)
    for n in range(1, 6):
        (d / f"R{n}.md").write_text(f"Prompt text of task R{n}.\n")
    return d


@pytest.fixture
def expected_path(tmp_path):
    p = tmp_path / "expected.json"
    p.write_text(json.dumps(EXPECTED))
    return p


# ---- structure checks -----------------------------------------------------


def test_r1_check():
    assert check("R1", good_answer("R1"))
    fenced = "```json\n" + good_answer("R1") + "\n```"
    assert check("R1", fenced)
    assert check("R1", "```\n" + good_answer("R1") + "\n```")
    assert not check("R1", fenced + "\n" + fenced)  # two fences
    assert not check("R1", "not json")
    assert not check("R1", json.dumps({"ranking": [
        {"id": "CVE-A", "verdict": "affected", "reason": "r"}]}))  # id missing
    assert not check("R1", json.dumps({"ranking": [
        {"id": i, "verdict": "affected", "reason": "r"} for i in ["CVE-A", "CVE-A"]]}))
    assert not check("R1", json.dumps({"ranking": [
        {"id": i, "verdict": "affected"} for i in R1_IDS]}))  # no reason key
    assert not check("R1", "[1]")


def test_r2_check():
    assert check("R2", good_answer("R2"))
    assert not check("R2", json.dumps({"advisories": [
        {"id": i, "reachable": "no", "reason": "r"} for i in R2_IDS]}))  # no check key
    assert not check("R2", json.dumps({"advisories": [
        {"id": i, "reachable": "no", "reason": "r", "check": "c"} for i in R2_IDS[:2]]}))


@pytest.mark.parametrize("task", ["R3", "R4"])
def test_validation_check(task):
    assert check(task, PY_GOOD)
    two_python = "```python\ndef test_a():\n    pass\n```\n```python\ndef test_b():\n    pass\n```\n" + MEANING
    assert not check(task, two_python)
    assert not check(task, "```python\ndef (:\n```\n" + MEANING)  # no parse
    assert not check(task, "```python\nx = 1\n```\n" + MEANING)  # no test_*
    assert not check(task, "```python\ndef test_a():\n    pass\n```\nno such line")
    assert not check(task, "```python\ndef test_a():\n    pass\n    # MEANING: inside\n```")
    assert not check(task, "def test_a():\n    pass\n" + MEANING)  # no fence
    assert not check(task, "```python\ndef test_a():\n    pass\n```\nMEANING:")  # no text


def test_r5_check():
    assert check("R5", good_answer("R5"))
    base = json.loads(good_answer("R5"))

    def with_(**kw):
        return json.dumps({**base, **kw})

    assert not check("R5", with_(rules=[{"cve": "CVE-X", "regex": "("}]))
    assert not check("R5", with_(rules=[{"cve": "CVE-X", "regex": "a"}]))  # one cve only
    assert not check("R5", with_(rules=[{"cve": "CVE-X", "regex": "a"},
                                        {"cve": "CVE-X", "regex": "b"}]))
    assert not check("R5", with_(incidents=[{"line": "4", "cve": "CVE-X", "succeeded": True}]))
    assert not check("R5", with_(incidents=[{"line": True, "cve": "CVE-X", "succeeded": True}]))
    assert not check("R5", with_(incidents=[{"line": 4, "cve": "CVE-X", "succeeded": "yes"}]))
    assert not check("R5", json.dumps({"incidents": []}))


# ---- fake API -------------------------------------------------------------


def task_of(body, prompts_dir):
    user = body["messages"][0]["content"]
    for p in prompts_dir.glob("R*.md"):
        if p.read_text() == user:
            return p.stem
    raise AssertionError("unknown prompt")


class FakeApi:
    def __init__(self, prompts_dir, mode="good", **flags):
        self.prompts_dir, self.mode, self.flags = prompts_dir, mode, flags
        self.requests = []

    def error(self, status, kind, msg):
        return httpx2.Response(status, json={"type": "error", "error": {
            "type": kind, "message": msg}}, headers={"request-id": "req_secret"})

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append(body)
        n = len(self.requests)
        model = body["model"]
        task = task_of(body, self.prompts_dir)
        mode = self.mode
        if mode == "429_once" and n == 1:
            return self.error(429, "rate_limit_error", "slow down")
        if mode == "500":
            return self.error(500, "api_error", "boom")
        if mode == "400":
            return self.error(400, "invalid_request_error", f"bad {FAKE_KEY}")
        if mode == "404_third" and n == 3:
            return self.error(404, "not_found_error", "no model")
        if mode == "500_third" and n >= 3:
            return self.error(500, "api_error", "boom")
        content = [{"type": "text", "text": good_answer(task)}]
        stop, extra = "end_turn", {}
        if mode == "refusal":
            content, stop = [], "refusal"
            extra["stop_details"] = {"type": "refusal", "category": "cyber",
                                     "explanation": "EXPLANATION-TEXT"}
        elif mode == "bad":
            content = [{"type": "text", "text": "not json at all"}]
        elif mode == "truncated":
            stop = "max_tokens"
        elif mode == "pause":
            stop = "pause_turn"
        elif mode == "fallback":
            content = content + [{"type": "fallback", "model": "x"}]
        shown = self.flags.get("shown", model)
        return httpx2.Response(200, json={
            "id": "msg_test", "type": "message", "role": "assistant",
            "model": shown, "content": content, "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 50}, **extra,
        }, headers={"request-id": "req_secret"})


@pytest.fixture
def run(tmp_path, capsys, prompts_dir, expected_path):
    def go(extra=(), mode="good", note="a note", **flags):
        api = FakeApi(prompts_dir, mode, **flags)
        client = anthropic.Anthropic(
            api_key=FAKE_KEY, max_retries=0,
            http_client=httpx2.Client(transport=httpx2.MockTransport(api)))
        argv = ["--run", "--repeats", "1", *extra]
        if note is not None:
            argv += ["--access-note", note]
        code = cm.main(
            argv, client=client, private_root=tmp_path / "private",
            public_root=tmp_path / "public", prompts_dir=prompts_dir,
            expected_path=expected_path)
        return code, capsys.readouterr().out, api
    go.records = lambda: [
        json.loads(p.read_text())
        for p in sorted((tmp_path / "private").glob("*/R*.json"))]
    go.summary = lambda: json.loads((tmp_path / "public" / "summary.json").read_text())
    return go


# ---- modes and guards -----------------------------------------------------


def test_default_is_dry_run_with_no_client_and_no_key(monkeypatch, capsys, prompts_dir):
    def boom(*a, **k):
        raise AssertionError("client built")
    monkeypatch.setattr(anthropic, "Anthropic", boom)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert cm.main([], prompts_dir=prompts_dir) == 0
    out = capsys.readouterr().out
    assert "calls: 100 in 10 rounds (none sent)" in out
    assert "worst-case cost bound" in out
    assert out.count(" prompt sha256 ") == 100
    assert "effort=high" in out and "concurrency=4" in out


def test_run_without_access_note_is_an_error(run):
    code, out, api = run(note=None)
    assert code == 2 and "--access-note" in out
    assert api.requests == []


def test_run_after_2026_12_14_prints_the_message(run, monkeypatch):
    monkeypatch.setattr(cm, "utc_today", lambda: date(2026, 12, 15))
    code, out, api = run()
    assert code == 2
    assert out.strip() == "ERROR: static keys end on 2026-12-14. No paid run."
    assert api.requests == []


def test_run_on_the_last_day_is_allowed(run, monkeypatch):
    monkeypatch.setattr(cm, "utc_today", lambda: date(2026, 12, 14))
    assert run(["--tasks", "R1"])[0] == 0


def test_missing_key_exits_2(capsys, monkeypatch, prompts_dir, expected_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    code = cm.main(["--run", "--access-note", "n"], prompts_dir=prompts_dir,
                   expected_path=expected_path)
    assert code == 2
    assert capsys.readouterr().out.strip() == "ERROR: missing ANTHROPIC_API_KEY"


# ---- outcomes -------------------------------------------------------------


def test_completed_on_every_task(run):
    code, out, api = run()
    assert code == 0
    assert {r["outcome"] for r in run.records()} == {"COMPLETED"}
    assert len(api.requests) == 10


def test_refused_records_category_and_prints_it(run):
    code, out, _ = run(["--tasks", "R1"], mode="refusal")
    assert code == 0
    assert "R1 claude-fable-5-2 #1: REFUSED (cyber)" in out
    assert run.records()[0]["stop_details"]["explanation"] == "EXPLANATION-TEXT"
    summary = run.summary()
    assert summary["calls"][0]["stop_category"] == "cyber"
    assert "EXPLANATION-TEXT" not in json.dumps(summary)


def test_not_completed(run):
    run(["--tasks", "R1"], mode="bad")
    assert {r["outcome"] for r in run.records()} == {"NOT_COMPLETED"}


def test_truncated(run):
    run(["--tasks", "R3"], mode="truncated")
    assert {r["outcome"] for r in run.records()} == {"TRUNCATED"}


def test_other_stop_reason_is_error(run):
    code, _, _ = run(["--tasks", "R1"], mode="pause")
    assert code == 4
    assert {r["outcome"] for r in run.records()} == {"ERROR"}


def test_error_400_is_recorded_not_retried_and_exits_4(run):
    code, out, api = run(["--tasks", "R1"], mode="400")
    assert code == 4
    assert len(api.requests) == 2
    rec = run.records()[0]
    assert (rec["outcome"], rec["attempts"], rec["error"]["status"]) == ("ERROR", 1, 400)
    assert "R1 claude-mythos-5-2 #1: ERROR (400 invalid_request_error)" in out


# ---- model identity -------------------------------------------------------


def test_model_mismatch_exits_3_after_writing_records(run):
    code, _, api = run(["--tasks", "R1", "--concurrency", "1"], shown="claude-other-1")
    assert code == 3
    assert len(api.requests) == 1  # the pending call of the round is skipped
    assert run.summary()["calls"][0]["model_returned"] == "claude-other-1"
    assert len(run.records()) == 1


def test_fallback_block_exits_3(run):
    code, _, _ = run(["--tasks", "R1"], mode="fallback")
    assert code == 3


def test_mismatch_stops_later_rounds(run):
    code, _, api = run(["--tasks", "R1", "--repeats", "3"], shown="claude-other-1")
    assert code == 3
    assert len(api.requests) == 2


# ---- request shape --------------------------------------------------------


def test_request_keys_and_same_text_for_both_models(run, prompts_dir):
    _, _, api = run(["--effort", "medium"])
    for b in api.requests:
        assert set(b) == {"model", "max_tokens", "system", "messages", "output_config"}
        assert b["system"] == SYSTEM_TEXT
        assert b["max_tokens"] == 16000
        assert b["output_config"] == {"effort": "medium"}
        assert len(b["messages"]) == 1 and b["messages"][0]["role"] == "user"
    by_task = {}
    for b in api.requests:
        by_task.setdefault(task_of(b, prompts_dir), set()).add(b["messages"][0]["content"])
    assert all(len(v) == 1 for v in by_task.values())
    assert {b["model"] for b in api.requests} == {MYTHOS, FABLE}


def test_default_effort_is_high(run):
    _, _, api = run(["--tasks", "R1"])
    assert {b["output_config"]["effort"] for b in api.requests} == {"high"}


# ---- privacy --------------------------------------------------------------


def test_key_never_written_or_printed(run, tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    _, out, _ = run(["--tasks", "R1"], mode="400")
    assert FAKE_KEY not in out
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert FAKE_KEY not in p.read_text()


def test_public_summary_holds_none_of_the_private_data(run, tmp_path):
    run(note="SECRET-NOTE")
    texts = [r["content"][0]["text"] for r in run.records()]
    for p in (tmp_path / "public").iterdir():
        body = p.read_text()
        assert all(t not in body for t in texts)
        assert "req_secret" not in body
        assert "SECRET-NOTE" not in body
    assert cm.ONE_KEY_SENTENCE in (tmp_path / "public" / "summary.md").read_text()
    assert run.summary()["note"] == cm.ONE_KEY_SENTENCE
    call = run.summary()["calls"][0]
    assert set(call) >= {
        "task_id", "repeat", "model_requested", "model_returned", "stop_reason",
        "stop_category", "outcome", "input_tokens", "output_tokens",
        "thinking_tokens", "utc_date", "prompt_sha256", "system_sha256",
        "output_sha256"}
    run_json = json.loads(next((tmp_path / "private").glob("*/run.json")).read_text())
    assert run_json["access_note"] == "SECRET-NOTE"


# ---- rounds, retries, stops ----------------------------------------------


def test_rounds_run_in_order_and_each_finishes_first(run, monkeypatch):
    events = []
    real = cm.run_call

    def wrapped(client, spec, *rest):
        events.append(("start", spec[2]))
        out = real(client, spec, *rest)
        events.append(("end", spec[2]))
        return out

    monkeypatch.setattr(cm, "run_call", wrapped)
    code, out, _ = run(["--repeats", "3", "--concurrency", "4"])
    assert code == 0
    assert len(events) == 2 * 10 * 3
    for rnd in (1, 2, 3):
        idx = [i for i, e in enumerate(events) if e[1] == rnd]
        assert idx == list(range(min(idx), max(idx) + 1))
    assert [e[1] for e in events if e[0] == "start"] == sorted(
        e[1] for e in events if e[0] == "start")
    assert "round 1:" in out and "round 3:" in out
    assert len(run.summary()["round_seconds"]) == 3


def test_429_is_retried_then_succeeds(run):
    code, _, api = run(["--tasks", "R1", "--models", MYTHOS], mode="429_once")
    assert code == 0
    rec = run.records()[0]
    assert (rec["outcome"], rec["attempts"]) == ("COMPLETED", 2)
    assert len(api.requests) == 2


def test_server_error_is_retried_three_times_then_errors(run):
    code, _, api = run(["--tasks", "R1", "--models", MYTHOS], mode="500")
    assert code == 4
    assert len(api.requests) == 4
    rec = run.records()[0]
    assert rec["outcome"] == "ERROR" and rec["attempts"] == 4


def test_refusal_is_never_retried(run):
    code, _, api = run(["--tasks", "R1"], mode="refusal")
    assert code == 0
    assert len(api.requests) == 2
    assert {r["attempts"] for r in run.records()} == {1}


def test_round_1_error_stops_run_with_exit_4(run):
    code, _, api = run(["--tasks", "R1", "--repeats", "3"], mode="400")
    assert code == 4
    assert len(api.requests) == 2
    assert run.summary()["calls"]
    assert len(run.records()) == 2


def test_status_404_after_round_1_stops_the_run(run):
    code, _, api = run(
        ["--tasks", "R1", "--repeats", "3", "--concurrency", "1"], mode="404_third")
    assert code == 4
    assert len(api.requests) == 3  # round 2 starts, its first call stops the run
    assert len(run.records()) == 3


def test_other_error_after_round_1_goes_on_and_exits_4(run):
    code, _, api = run(
        ["--tasks", "R1", "--repeats", "3", "--concurrency", "1"], mode="500_third")
    assert code == 4
    assert len(run.records()) == 6  # all three rounds ran
    outcomes = [r["outcome"] for r in run.records()]
    assert outcomes.count("ERROR") == 4


def test_concurrency_4_gives_same_records_as_concurrency_1(
        tmp_path, capsys, prompts_dir, expected_path):
    def one(sub, conc):
        root = tmp_path / sub
        api = FakeApi(prompts_dir)
        client = anthropic.Anthropic(
            api_key=FAKE_KEY, max_retries=0,
            http_client=httpx2.Client(transport=httpx2.MockTransport(api)))
        cm.main(["--run", "--access-note", "n", "--repeats", "2",
                 "--concurrency", str(conc)], client=client,
                private_root=root / "p", public_root=root / "q",
                prompts_dir=prompts_dir, expected_path=expected_path)
        out = {}
        for p in (root / "p").glob("*/R*.json"):
            r = json.loads(p.read_text())
            r.pop("utc"), r.pop("request_id")
            out[p.name] = r
        return out
    a, b = one("a", 1), one("b", 4)
    assert a == b and len(a) == 20


# ---- the frozen files -----------------------------------------------------


def test_frozen_expected_ids_appear_in_the_real_prompts():
    expected = json.loads(cm.EXPECTED.read_text())
    _, prompts = cm.load_prompts(cm.PROMPTS)
    for task in ("R1", "R2"):
        assert len(expected[task]["ids"]) == len(set(expected[task]["ids"]))
        for i in expected[task]["ids"]:
            assert prompts[task].count(f'"VulnerabilityID": "{i}"') == 1
    log = (cm.ROOT / "scripts/showcase/fixtures/access.log").read_text().splitlines()
    for item in expected["R5"]["incidents"] + expected["R5"]["optional"]:
        line = log[item["line"] - 1]
        assert (("DIAGNOSTICS" in line) if item["cve"] == "CVE-2026-48817"
                else ("/../" in line)) and re.search(r"\b(200|404)\b", line)
        assert (" 200 " in line) == item["succeeded"]
