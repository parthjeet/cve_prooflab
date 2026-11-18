"""The model loop of the AI security gate: requests, tool dispatch, limits, failures.

run_agent never raises for a model, API, or limit failure. It returns an
AgentResult whose `error` field holds the exact message (without the
"ERROR: " prefix), or None on success.
"""
import time
from dataclasses import dataclass, field

import anthropic

import tools

TOOL_LIMIT_TEXT = "ERROR: tool-call limit reached; answer now"
NO_ACCESS = "this key cannot use claude-mythos-5-2. No fallback model is used."
CACHE = {"type": "ephemeral"}


@dataclass
class AgentResult:
    model_requested: str
    model_returned: str | None = None
    final_stop_reason: str | None = None
    answer_text: str | None = None
    error: str | None = None
    error_request_id: str | None = None
    requests: list = field(default_factory=list)
    tool_calls: list = field(default_factory=list)
    totals: dict = field(default_factory=lambda: {
        "requests": 0, "tool_calls": 0, "input_tokens": 0,
        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        "output_tokens": 0, "total_input_tokens": 0,
    })


def tool_arg(tool_input):
    """The one location argument of a tool call: path, dir, or glob. No other input."""
    if isinstance(tool_input, dict):
        for key in ("path", "dir", "path_glob"):
            if isinstance(tool_input.get(key), str):
                return tool_input[key]
    return ""


def add_usage(totals, usage):
    inp = usage.get("input_tokens") or 0
    create = usage.get("cache_creation_input_tokens") or 0
    read = usage.get("cache_read_input_tokens") or 0
    totals["input_tokens"] += inp
    totals["cache_creation_input_tokens"] += create
    totals["cache_read_input_tokens"] += read
    totals["output_tokens"] += usage.get("output_tokens") or 0
    totals["total_input_tokens"] += inp + create + read


def limit_hit(totals, config, started, clock):
    if totals["total_input_tokens"] >= config.max_input_tokens:
        return "input tokens"
    if totals["output_tokens"] >= config.max_output_tokens:
        return "output tokens"
    if clock() - started >= config.max_seconds:
        return "wall clock"
    return None


def run_agent(client, *, system, first_message, toolbox, config, model, answer_schema,
              clock=time.monotonic):
    result = AgentResult(model_requested=model)
    started = clock()
    system_blocks = [{"type": "text", "text": system, "cache_control": CACHE}]
    tool_defs = [*tools.TOOL_DEFINITIONS]
    tool_defs[-1] = {**tool_defs[-1], "cache_control": CACHE}
    messages = [{"role": "user", "content": first_message}]

    def fail(message, request_id=None):
        result.error = message
        result.error_request_id = request_id
        return result

    while True:
        if result.totals["requests"] >= config.max_requests:
            return fail("limit reached: requests")
        which = limit_hit(result.totals, config, started, clock)
        if which:
            return fail(f"limit reached: {which}")
        try:
            response = client.messages.create(
                model=model,
                max_tokens=config.max_tokens,
                system=system_blocks,
                tools=tool_defs,
                messages=messages,
                output_config={"effort": config.effort,
                               "format": {"type": "json_schema", "schema": answer_schema}},
            )
        except anthropic.APIStatusError as e:
            if e.status_code in (401, 403, 404):
                return fail(NO_ACCESS, e.request_id)
            return fail(f"API error {e.status_code} {e.type}", e.request_id)
        except anthropic.APIConnectionError:
            return fail("API error connection")

        details = getattr(response, "stop_details", None)
        usage = response.usage.model_dump(mode="json")
        result.requests.append({
            "request_id": getattr(response, "_request_id", None),
            "stop_reason": response.stop_reason,
            "stop_details": details.model_dump(mode="json") if details else None,
            "usage": usage,
        })
        result.totals["requests"] += 1
        add_usage(result.totals, usage)
        result.model_returned = response.model
        result.final_stop_reason = response.stop_reason

        if response.model != model:
            return fail(f"model mismatch: {response.model}")
        if any(getattr(b, "type", None) == "fallback" for b in response.content):
            return fail("fallback block in response")
        reason = response.stop_reason
        if reason == "refusal":
            category = getattr(details, "category", None)
            return fail(f"model refused (category: {category})")
        if reason == "max_tokens":
            return fail("invalid answer: cut by max_tokens")
        if reason == "end_turn":
            which = limit_hit(result.totals, config, started, clock)
            if which:
                return fail(f"limit reached: {which}")
            result.answer_text = "".join(
                b.text for b in response.content if getattr(b, "type", None) == "text")
            return result
        uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if reason != "tool_use" or not uses:
            return fail(f"unexpected stop_reason {reason}")

        results = []
        for block in uses:
            result.totals["tool_calls"] += 1
            result.tool_calls.append({"name": block.name, "path": tool_arg(block.input)})
            if result.totals["tool_calls"] > config.max_tool_calls:
                text = TOOL_LIMIT_TEXT
            else:
                text = tools.dispatch(toolbox, block.name, block.input)
            results.append({"type": "tool_result", "tool_use_id": block.id, "content": text})
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": results})
