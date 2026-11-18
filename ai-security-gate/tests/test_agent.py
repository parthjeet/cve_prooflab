import json
import sys
from dataclasses import replace
from pathlib import Path

import anthropic
import httpx2
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import gate  # noqa: E402
import tools  # noqa: E402

MODEL = "claude-mythos-5-2"
SCHEMA = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}


def message(content, stop_reason="end_turn", model=MODEL, usage=None, details=None):
    return {
        "id": "msg_test", "type": "message", "role": "assistant", "model": model,
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "stop_details": details,
        "usage": usage or {"input_tokens": 10, "output_tokens": 5},
    }


def text(value):
    return {"type": "text", "text": value}


def tool_use(name="read_file", tool_id="toolu_1", **inp):
    inp = inp or {"path": "a.txt", "start_line": 1, "end_line": 2}
    return {"type": "tool_use", "id": tool_id, "name": name, "input": inp}


class FakeApi:
    """Replies with the scripted responses in order; the last one repeats."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, request):
        self.requests.append(json.loads(request.content))
        i = min(len(self.requests), len(self.replies)) - 1
        reply = self.replies[i]
        if isinstance(reply, Exception):
            raise reply
        status, body = reply if isinstance(reply, tuple) else (200, reply)
        return httpx2.Response(status, json=body, headers={"request-id": f"req_{i + 1}"})


def error_body(kind):
    return {"type": "error", "error": {"type": kind, "message": "x"}}


REAL_CLIENT = anthropic.Anthropic


def make_client(api):
    return REAL_CLIENT(api_key="sk-test-not-real", max_retries=0,
                               http_client=httpx2.Client(transport=httpx2.MockTransport(api)))


@pytest.fixture
def box(tmp_path):
    (tmp_path / "a.txt").write_text("one\ntwo\nthree\n")
    return tools.Toolbox(tmp_path, "base", "head")


def run(api, box, config=None, **kw):
    return agent.run_agent(make_client(api), system="sys {x}", first_message="first",
                           toolbox=box, config=config or gate.Config(), model=MODEL,
                           answer_schema=SCHEMA, **kw)


def test_two_request_tool_loop_returns_answer(box):
    api = FakeApi(message([tool_use()], "tool_use"), message([text('{"a"'), text(': 1}')]))
    r = run(api, box)
    assert r.error is None
    assert r.answer_text == '{"a": 1}'
    assert r.tool_calls == [{"name": "read_file", "path": "a.txt"}]
    assert r.model_returned == MODEL and r.final_stop_reason == "end_turn"
    assert [q["request_id"] for q in r.requests] == ["req_1", "req_2"]
    assert r.totals["requests"] == 2 and r.totals["output_tokens"] == 10
    second = api.requests[1]["messages"]
    assert second[1]["role"] == "assistant"
    result = second[2]["content"][0]
    assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1"
    assert "1\tone" in result["content"]


def test_request_shape(box):
    api = FakeApi(message([text("{}")]))
    run(api, box)
    body = api.requests[0]
    assert set(body) == {"model", "max_tokens", "system", "tools", "messages", "output_config"}
    assert body["model"] == MODEL and body["max_tokens"] == gate.Config().max_tokens
    assert body["system"] == [{"type": "text", "text": "sys {x}",
                               "cache_control": {"type": "ephemeral"}}]
    assert body["messages"] == [{"role": "user", "content": [
        {"type": "text", "text": "first", "cache_control": {"type": "ephemeral"}}]}]
    assert body["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    assert all("cache_control" not in t for t in body["tools"][:-1])
    assert [t["name"] for t in body["tools"]] == [t["name"] for t in tools.TOOL_DEFINITIONS]
    assert "cache_control" not in tools.TOOL_DEFINITIONS[-1]
    assert body["output_config"] == {"effort": "medium",
                                     "format": {"type": "json_schema", "schema": SCHEMA}}
    assert "fallbacks" not in body


def test_tool_call_limit_text_after_the_limit(box):
    two = message([tool_use(tool_id="t1"), tool_use(tool_id="t2")], "tool_use")
    api = FakeApi(two, message([text("{}")]))
    r = run(api, box, replace(gate.Config(), max_tool_calls=1))
    assert r.error is None and r.totals["tool_calls"] == 2
    results = api.requests[1]["messages"][2]["content"]
    assert "one" in results[0]["content"]
    assert results[1]["content"] == "ERROR: tool-call limit reached; answer now"


def test_request_limit(box):
    api = FakeApi(message([tool_use()], "tool_use"))
    r = run(api, box, replace(gate.Config(), max_requests=2))
    assert r.error == "limit reached: requests"
    assert len(api.requests) == 2


def test_input_token_limit_counts_cache_tokens(box):
    usage = {"input_tokens": 10, "output_tokens": 1, "cache_creation_input_tokens": 60,
             "cache_read_input_tokens": 30}
    api = FakeApi(message([tool_use()], "tool_use", usage=usage))
    r = run(api, box, replace(gate.Config(), max_input_tokens=100))
    assert r.error == "limit reached: input tokens"
    assert r.totals["total_input_tokens"] == 100


def test_output_token_limit(box):
    api = FakeApi(message([tool_use()], "tool_use", usage={"input_tokens": 1, "output_tokens": 50}))
    r = run(api, box, replace(gate.Config(), max_output_tokens=50))
    assert r.error == "limit reached: output tokens"


def test_wall_clock_limit(box):
    ticks = iter([0, 5, 700, 700, 700])
    api = FakeApi(message([tool_use()], "tool_use"))
    r = run(api, box, clock=lambda: next(ticks))
    assert r.error == "limit reached: wall clock"


def test_model_mismatch(box):
    r = run(FakeApi(message([text("{}")], model="claude-other-1")), box)
    assert r.error == "model mismatch: claude-other-1"
    assert r.model_returned == "claude-other-1"


def test_refusal_with_category(box):
    body = message([], "refusal", details={"type": "refusal", "category": "cyber",
                                           "explanation": "secret words"})
    r = run(FakeApi(body), box)
    assert r.error == "model refused (category: cyber)"
    assert r.requests[0]["stop_details"]["explanation"] == "secret words"


def test_max_tokens_stop(box):
    r = run(FakeApi(message([text("{")], "max_tokens")), box)
    assert r.error == "invalid answer: cut by max_tokens"


def test_other_stop_reason(box):
    r = run(FakeApi(message([text("x")], "pause_turn")), box)
    assert r.error == "unexpected stop_reason pause_turn"


def test_fallback_block(box):
    r = run(FakeApi(message([{"type": "fallback", "model": "x"}, text("{}")])), box)
    assert r.error == "fallback block in response"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_key_cannot_use_model(box, status):
    r = run(FakeApi((status, error_body("authentication_error"))), box)
    assert r.error == "this key cannot use claude-mythos-5-2. No fallback model is used."


def test_other_status_error_has_type_and_request_id(box):
    r = run(FakeApi((500, error_body("api_error"))), box)
    assert r.error == "API error 500 api_error"
    assert r.error_request_id == "req_1"


def test_connection_error(box):
    r = run(FakeApi(httpx2.ConnectError("down")), box)
    assert r.error == "API error connection"
