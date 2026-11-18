"""Offline tests for compare_models.py. No network: the client uses a mock
transport from httpx2 (anthropic 2.10.0 builds on httpx2, not httpx)."""
import json
import sys
from pathlib import Path

import anthropic
import httpx2
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import compare_models as cm  # noqa: E402

FAKE_KEY = "sk-test-not-real"
MYTHOS, FABLE = "claude-mythos-5-2", "claude-fable-5-2"
SYSTEM, TASKS = cm.load_prompts(cm.PROMPTS)

R3_GOOD = "```python\ndef test_x():\n    assert True\n```\nMeaning: pass means open, fail means closed."


@pytest.fixture(autouse=True)
def no_retry_delay(monkeypatch):
    monkeypatch.setattr(cm, "RETRY_DELAYS", (0, 0, 0))


def good_answer(task):
    if task == "R1":
        ids = cm.prompt_ids(TASKS["R1"])
        return json.dumps({"findings": [
            {"id": i, "rank": n, "verdict": "monitor", "reason": "r"}
            for n, i in enumerate(ids, 1)]})
    if task == "R2":
        return "```json\n" + json.dumps({"advisories": [
            {"id": i, "reachable": "no", "reason": "r", "check": "c"}
            for i in sorted(cm.R2_IDS)]}) + "\n```"
    if task in ("R3", "R4"):
        return R3_GOOD
    return json.dumps({
        "incidents": [{"line": 4, "cve": "CVE-2023-29159", "succeeded": True}],
        "rules": [{"cve": "CVE-2023-29159", "regex": r"\.\./static_disallow"}]})


BAD_ANSWER = {
    "R1": lambda: json.dumps({"findings": [{"id": "CVE-2024-47874", "verdict": "monitor"}]}),
    "R2": lambda: json.dumps({"advisories": [
        {"id": i, "reachable": "maybe"} for i in sorted(cm.R2_IDS)]}),
    "R3": lambda: "```python\ndef (:\n```\nMeaning: x",
    "R4": lambda: "```python\nx = 1\n```\nno summary line",
    "R5": lambda: json.dumps({"incidents": [{"line": 41, "cve": "CVE-2023-29159",
                                             "succeeded": True}], "rules": []}),
}


def task_of(body):
    user = body["messages"][0]["content"]
    for name, text in TASKS.items():
        if text == user:
            return name
    raise AssertionError("unknown prompt")


class FakeApi:
    def __init__(self, mode="good", **flags):
        self.mode, self.flags, self.requests = mode, flags, []

    def __call__(self, request):
        body = json.loads(request.content)
        self.requests.append(body)
        model = body["model"]
        if self.mode == "429_once" and len(self.requests) == 1:
            return httpx2.Response(429, json={"type": "error", "error": {
                "type": "rate_limit_error", "message": "slow down"}})
        if self.mode == "500":
            return httpx2.Response(500, json={"type": "error", "error": {
                "type": "api_error", "message": "boom"}})
        if self.mode == "error":
            return httpx2.Response(400, json={"type": "error", "error": {
                "type": "invalid_request_error",
                "message": f"bad request {FAKE_KEY}"}},
                headers={"request-id": "req_secret"})
        content = [{"type": "text", "text": good_answer(task_of(body))}]
        stop = "end_turn"
        extra = {}
        if self.mode == "refusal":
            content, stop = [], "refusal"
            extra["stop_details"] = {"type": "refusal", "category": "cyber",
                                     "explanation": "EXPLANATION-TEXT"}
        elif self.mode == "bad":
            content = [{"type": "text", "text": BAD_ANSWER[task_of(body)]()}]
        elif self.mode == "truncated":
            stop = "max_tokens"
        elif self.mode == "fallback":
            content = content + [{"type": "fallback", "model": "x"}]
        shown = self.flags.get("shown", model)
        return httpx2.Response(200, json={
            "id": "msg_test", "type": "message", "role": "assistant",
            "model": shown, "content": content, "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 100, "output_tokens": 50}, **extra,
        }, headers={"request-id": "req_secret"})


def run(tmp_path, capsys, extra=(), mode="good", **flags):
    api = FakeApi(mode, **flags)
    client = anthropic.Anthropic(
        api_key=FAKE_KEY, max_retries=0,
        http_client=httpx2.Client(transport=httpx2.MockTransport(api)))
    code = cm.main(
        ["--repeats", "1", *extra], client=client,
        private_root=tmp_path / "private", public_root=tmp_path / "public")
    out = capsys.readouterr().out
    return code, out, api


def private_records(tmp_path):
    return [json.loads(p.read_text())
            for p in sorted((tmp_path / "private").glob("*/R*.json"))]


def test_dry_run_makes_no_network_call_and_builds_no_client(capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("client built")
    monkeypatch.setattr(anthropic, "Anthropic", boom)
    assert cm.main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "calls: 100" in out
    assert "worst-case cost bound" in out
    for name, text in TASKS.items():
        assert f"{name} sha256 {cm.sha256(text)}" in out


def test_completed_for_good_answers_on_every_task(tmp_path, capsys):
    code, out, api = run(tmp_path, capsys)
    assert code == 0
    assert {r["outcome"] for r in private_records(tmp_path)} == {"COMPLETED"}
    assert len(api.requests) == 10


def test_refused_records_category_and_prints_it(tmp_path, capsys):
    code, out, _ = run(tmp_path, capsys, ["--tasks", "R1"], mode="refusal")
    assert code == 0
    assert "R1 claude-fable-5-2 #1: REFUSED (cyber)" in out
    rec = private_records(tmp_path)[0]
    assert rec["stop_details"]["explanation"] == "EXPLANATION-TEXT"
    summary = json.loads((tmp_path / "public" / "summary.json").read_text())
    assert summary["calls"][0]["stop_details_category"] == "cyber"
    assert "EXPLANATION-TEXT" not in json.dumps(summary)


def test_not_completed_truncated_and_error(tmp_path, capsys):
    run(tmp_path, capsys, ["--tasks", "R1"], mode="bad")
    assert {r["outcome"] for r in private_records(tmp_path)} == {"NOT_COMPLETED"}


def test_truncated(tmp_path, capsys):
    run(tmp_path, capsys, ["--tasks", "R3"], mode="truncated")
    assert {r["outcome"] for r in private_records(tmp_path)} == {"TRUNCATED"}


def test_error_400(tmp_path, capsys):
    code, out, api = run(tmp_path, capsys, ["--tasks", "R1"], mode="error")
    assert code == 4
    assert len(api.requests) == 2  # 400 is not retried
    rec = private_records(tmp_path)[0]
    assert rec["attempts"] == 1
    assert rec["outcome"] == "ERROR"
    assert rec["error"]["status"] == 400
    assert rec["error"]["error_type"] == "invalid_request_error"
    assert "R1 claude-mythos-5-2 #1: ERROR (400 invalid_request_error)" in out


@pytest.mark.parametrize("task", ["R1", "R2", "R3", "R4", "R5"])
def test_structure_check_accepts_good_and_rejects_bad(task):
    check = cm.CHECKS[task]
    assert check(good_answer(task), TASKS[task])[0] is True
    assert check(BAD_ANSWER[task](), TASKS[task])[0] is False
    assert check("not json at all", TASKS[task])[0] is False


def test_r1_rejects_duplicate_id_and_r5_rejects_bad_regex():
    ids = cm.prompt_ids(TASKS["R1"])
    assert len(ids) == 8
    dup = json.dumps({"findings": [
        {"id": ids[0], "verdict": "monitor"} for _ in ids]})
    assert cm.check_r1(dup, TASKS["R1"])[0] is False
    bad = json.dumps({"incidents": [], "rules": [{"cve": "x", "regex": "("}]})
    assert cm.check_r5(bad, "")[0] is False


def test_model_mismatch_exits_3_and_still_writes_records(tmp_path, capsys):
    code, out, _ = run(tmp_path, capsys, ["--tasks", "R1"], shown="claude-other-1")
    assert code == 3
    assert (tmp_path / "public" / "summary.json").exists()
    assert len(private_records(tmp_path)) == 2


def test_fallback_block_exits_3(tmp_path, capsys):
    code, _, _ = run(tmp_path, capsys, ["--tasks", "R1"], mode="fallback")
    assert code == 3


def test_key_never_written_or_printed(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    _, out, _ = run(tmp_path, capsys, ["--tasks", "R1", "--access-note", "n"], mode="error")
    assert FAKE_KEY not in out
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert FAKE_KEY not in p.read_text()


def test_public_summary_holds_no_model_text_or_private_fields(tmp_path, capsys):
    run(tmp_path, capsys, ["--access-note", "SECRET-NOTE"])
    texts = [r["content"][0]["text"] for r in private_records(tmp_path)]
    for p in (tmp_path / "public").iterdir():
        body = p.read_text()
        for t in texts:
            assert t not in body
        assert "req_secret" not in body
        assert "SECRET-NOTE" not in body
    run_json = json.loads(next((tmp_path / "private").glob("*/run.json")).read_text())
    assert run_json["access_note"] == "SECRET-NOTE"


def test_requests_have_no_fallbacks_and_same_text_for_both_models(tmp_path, capsys):
    _, _, api = run(tmp_path, capsys, ["--effort", "medium"])
    assert all("fallbacks" not in b for b in api.requests)
    assert all(b["output_config"] == {"effort": "medium"} for b in api.requests)
    for b in api.requests:
        assert b["system"] == SYSTEM
        assert "temperature" not in b and "tools" not in b
    by_task = {}
    for b in api.requests:
        by_task.setdefault(task_of(b), set()).add(b["messages"][0]["content"])
    assert all(len(v) == 1 for v in by_task.values())
    assert {b["model"] for b in api.requests} == {MYTHOS, FABLE}


def test_concurrency_4_gives_same_records_as_concurrency_1(tmp_path, capsys):
    def keyed(root):
        out = {}
        for p in (root / "private").glob("*/R*.json"):
            r = json.loads(p.read_text())
            for k in ("utc", "request_id"):
                r.pop(k, None)
            out[p.name] = r
        return out
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    run(a, capsys, ["--concurrency", "1", "--repeats", "2"])
    run(b, capsys, ["--concurrency", "4", "--repeats", "2"])
    assert keyed(a) == keyed(b) and len(keyed(a)) == 20


def test_rounds_run_in_order_and_each_finishes_first(tmp_path, capsys, monkeypatch):
    events = []
    real = cm.run_call

    def wrapped(client, spec, system, args):
        events.append(("start", spec[2]))
        out = real(client, spec, system, args)
        events.append(("end", spec[2]))
        return out

    monkeypatch.setattr(cm, "run_call", wrapped)
    code, out, _ = run(tmp_path, capsys, ["--repeats", "3", "--concurrency", "4"])
    assert code == 0
    assert len(events) == 2 * 10 * 3
    for rnd in (1, 2, 3):
        idx = [i for i, e in enumerate(events) if e[1] == rnd]
        assert idx == list(range(min(idx), max(idx) + 1))  # rounds do not interleave
    assert [e[1] for e in events if e[0] == "start"] == sorted(
        e[1] for e in events if e[0] == "start")
    assert "round 1:" in out and "round 3:" in out
    summary = json.loads((tmp_path / "public" / "summary.json").read_text())
    assert len(summary["round_seconds"]) == 3


def test_429_is_retried_then_succeeds(tmp_path, capsys):
    code, _, api = run(
        tmp_path, capsys,
        ["--tasks", "R1", "--models", MYTHOS], mode="429_once")
    assert code == 0
    rec = private_records(tmp_path)[0]
    assert rec["outcome"] == "COMPLETED"
    assert rec["attempts"] == 2
    assert len(api.requests) == 2


def test_server_error_is_retried_three_times_then_errors(tmp_path, capsys):
    code, _, api = run(
        tmp_path, capsys, ["--tasks", "R1", "--models", MYTHOS], mode="500")
    assert code == 4
    assert len(api.requests) == 4
    rec = private_records(tmp_path)[0]
    assert rec["outcome"] == "ERROR" and rec["attempts"] == 4


def test_refusal_is_never_retried(tmp_path, capsys):
    code, _, api = run(tmp_path, capsys, ["--tasks", "R1"], mode="refusal")
    assert code == 0
    assert len(api.requests) == 2
    assert {r["attempts"] for r in private_records(tmp_path)} == {1}


def test_round_1_error_stops_run_with_exit_4(tmp_path, capsys):
    code, out, api = run(
        tmp_path, capsys, ["--tasks", "R1", "--repeats", "3"], mode="error")
    assert code == 4
    assert len(api.requests) == 2  # only round 1
    assert (tmp_path / "public" / "summary.json").exists()
    assert len(private_records(tmp_path)) == 2


def test_mismatch_stops_after_the_round_with_exit_3(tmp_path, capsys):
    code, _, api = run(
        tmp_path, capsys, ["--tasks", "R1", "--repeats", "3"], shown="claude-other-1")
    assert code == 3
    assert len(api.requests) == 2
