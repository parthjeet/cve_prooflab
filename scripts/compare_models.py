#!/usr/bin/env python3
"""Frozen model comparison ("run 1"): five defensive security tasks, sent with
identical prompts and settings to each model through the Messages API.

The default mode is a dry run: it builds every request, sends none, reads no
key, and prints the plan and a worst-case cost bound. A paid run needs --run
and --access-note together:

    uv run --python 3.12 --no-project --with anthropic==2.10.0 \\
        scripts/compare_models.py --run --access-note "free text"

Calls go in rounds. Round r sends every task x model cell once, with at most 4
calls in flight, and ends before round r+1 starts. A refusal is never retried.
A connection error, HTTP 429, or HTTP 5xx is retried up to 3 times.

Outputs:
- docs/showcase-runs/<run_id>/ (private, gitignored): full records, model text.
- reports/showcase/summary.{json,md} (public): counts and token totals only.
  No model text, request ID, explanation, or access note goes there.

Exit: 0 done; 2 refused to start (no --access-note, past 2026-12-14, no key);
3 a response named another model or held a fallback block; 4 a call ended in
ERROR (the run stops after round 1, or after a status 400/401/403/404).
"""
import argparse
import ast
import hashlib
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "scripts" / "showcase" / "prompts"
EXPECTED = ROOT / "scripts" / "showcase" / "expected.json"
PRIVATE = ROOT / "docs" / "showcase-runs"
PUBLIC = ROOT / "reports" / "showcase"

DEFAULT_MODELS = "claude-mythos-5-2,claude-fable-5-2"
DEFAULT_TASKS = "R1,R2,R3,R4,R5"
PRICE_INPUT = 8.0
PRICE_OUTPUT = 40.0
OUTCOMES = ("COMPLETED", "NOT_COMPLETED", "REFUSED", "TRUNCATED", "ERROR")
RETRY_DELAYS = (2, 5, 10)  # seconds before retry 1, 2, 3
MAX_CONCURRENCY = 4
STOP_STATUSES = (400, 401, 403, 404)
LAST_KEY_DAY = date(2026, 12, 14)
KEY_END_MESSAGE = "ERROR: static keys end on 2026-12-14. No paid run."
ONE_KEY_SENTENCE = "Both models were called with one key from one workspace."


# ---- helpers --------------------------------------------------------------


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_today():
    return datetime.now(timezone.utc).date()


def clean(text):
    """Remove the key from any text before it is stored or printed."""
    text = "" if text is None else str(text)
    key = os.environ.get("ANTHROPIC_API_KEY")
    return text.replace(key, "[redacted]") if key else text


def load_prompts(prompts_dir):
    system = (prompts_dir / "system.md").read_text()
    tasks = {p.stem: p.read_text() for p in sorted(prompts_dir.glob("R[0-9].md"))}
    return system, tasks


# ---- structure checks -----------------------------------------------------

FENCE = re.compile(r"```(\w*)[ \t]*\n(.*?)```", re.DOTALL)


def parse_json(text):
    """Whole text as JSON, else the content of exactly one fenced block."""
    text = text.strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    blocks = FENCE.findall(text)
    if len(blocks) == 1 and blocks[0][0] in ("json", ""):
        return json.loads(blocks[0][1])
    raise ValueError("no JSON")


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _json_obj(text):
    try:
        data = parse_json(text)
    except (ValueError, TypeError):
        return None, "not valid JSON"
    if not isinstance(data, dict):
        return None, "JSON is not an object"
    return data, None


def _check_list(data, key, keys, expected_ids):
    items = data.get(key)
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        return False, f"{key} is not a list of objects"
    for item in items:
        missing = [k for k in keys if k not in item]
        if missing:
            return False, f"entry lacks {missing}"
    ids = [i["id"] for i in items]
    if sorted(map(str, ids)) != sorted(expected_ids):
        return False, f"ids differ: got {sorted(map(str, ids))}"
    return True, "ok"


def check_r1(text, expected):
    data, err = _json_obj(text)
    if err:
        return False, err
    return _check_list(data, "ranking", ("id", "verdict", "reason"), expected["ids"])


def check_r2(text, expected):
    data, err = _json_obj(text)
    if err:
        return False, err
    return _check_list(
        data, "advisories", ("id", "reachable", "reason", "check"), expected["ids"]
    )


def check_validation(text, expected):
    blocks = FENCE.findall(text)
    python = [b for b in blocks if b[0] == "python"]
    if len(python) != 1:
        return False, "not exactly one python block"
    try:
        tree = ast.parse(python[0][1])
    except SyntaxError as exc:
        return False, f"python block does not parse: {exc.msg}"
    if not any(
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name.startswith("test_")
        for n in ast.walk(tree)
    ):
        return False, "no test_* function"
    outside = FENCE.sub("", text)
    if not re.search(r"^MEANING:[ \t]*\S", outside, re.MULTILINE):
        return False, 'no line outside the block beginning "MEANING:"'
    return True, "ok"


def check_r5(text, expected):
    data, err = _json_obj(text)
    if err:
        return False, err
    incidents, rules = data.get("incidents"), data.get("rules")
    if not isinstance(incidents, list) or not isinstance(rules, list):
        return False, "incidents or rules missing or not a list"
    for item in incidents:
        if not isinstance(item, dict):
            return False, "incident is not an object"
        if not _is_int(item.get("line")):
            return False, f"bad line {item.get('line')!r}"
        if not isinstance(item.get("cve"), str):
            return False, "cve is not a string"
        if not isinstance(item.get("succeeded"), bool):
            return False, "succeeded is not a boolean"
    for item in rules:
        if not isinstance(item, dict) or not isinstance(item.get("regex"), str):
            return False, "rule without a regex string"
        try:
            re.compile(item["regex"])
        except re.error as exc:
            return False, f"regex does not compile: {exc}"
    if sorted(str(r.get("cve")) for r in rules) != sorted(expected["cves"]):
        return False, "rule cve values differ from the expected two"
    return True, "ok"


CHECKS = {
    "R1": check_r1, "R2": check_r2, "R3": check_validation,
    "R4": check_validation, "R5": check_r5,
}


# ---- one call -------------------------------------------------------------


def describe_error(exc):
    import anthropic

    if isinstance(exc, anthropic.APIStatusError):
        return {
            "kind": "api_status",
            "status": exc.status_code,
            "error_type": exc.type,
            "message": clean(exc.api_message or exc.message),
            "request_id": exc.request_id,
        }
    return {
        "kind": "connection",
        "status": None,
        "error_type": type(exc).__name__,
        "message": clean(exc),
        "request_id": None,
    }


def build_request(model, system, prompt, args):
    return {
        "model": model,
        "max_tokens": args.max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
        "output_config": {"effort": args.effort},
    }


def retryable(exc):
    import anthropic

    if isinstance(exc, anthropic.APIStatusError):
        return exc.status_code == 429 or exc.status_code >= 500
    return isinstance(exc, anthropic.APIConnectionError)


def classify(resp, task, expected):
    """Return (outcome, check detail) for a response."""
    reason = resp.stop_reason
    if reason == "refusal":
        return "REFUSED", "refusal"
    if reason == "max_tokens":
        return "TRUNCATED", "max_tokens"
    if reason != "end_turn":
        return "ERROR", f"unexpected stop_reason {reason}"
    text = "".join(b.text for b in resp.content if b.type == "text")
    ok, detail = CHECKS[task](text, expected.get(task, {}))
    return ("COMPLETED" if ok else "NOT_COMPLETED"), detail


def run_call(client, spec, system, args, expected):
    import anthropic

    task, model, repeat, prompt = spec
    rec = {
        "task_id": task, "repeat": repeat, "model_requested": model,
        "model_returned": None, "request_id": None, "content": [],
        "stop_reason": None, "stop_details": None, "usage": None,
        "outcome": None, "check_detail": None, "error": None,
        "fallback_blocks": 0, "attempts": 0,
        "prompt_sha256": sha256(prompt), "system_sha256": sha256(system),
        "output_sha256": None, "output_chars": None,
    }
    resp = None
    for attempt in range(len(RETRY_DELAYS) + 1):
        rec["attempts"] = attempt + 1
        try:
            resp = client.messages.create(**build_request(model, system, prompt, args))
            rec["error"] = None
            break
        except anthropic.APIError as exc:
            rec["error"] = describe_error(exc)
            if not retryable(exc) or attempt == len(RETRY_DELAYS):
                break
            time.sleep(RETRY_DELAYS[attempt])
    if resp is None:
        rec["outcome"] = "ERROR"
        rec["check_detail"] = "api error"
    else:
        details = getattr(resp, "stop_details", None)
        text = "".join(b.text for b in resp.content if b.type == "text")
        rec.update(
            model_returned=resp.model,
            request_id=getattr(resp, "_request_id", None),
            content=[b.model_dump(mode="json") for b in resp.content],
            stop_reason=resp.stop_reason,
            stop_details=details.model_dump(mode="json") if details else None,
            usage=resp.usage.model_dump(mode="json"),
            fallback_blocks=sum(1 for b in resp.content if b.type == "fallback"),
            output_sha256=sha256(text),
            output_chars=len(text),
        )
        rec["outcome"], rec["check_detail"] = classify(resp, task, expected)
        if rec["outcome"] == "ERROR":
            rec["error"] = {
                "kind": "stop_reason", "status": None,
                "error_type": f"stop_reason:{resp.stop_reason}",
                "message": rec["check_detail"], "request_id": None,
            }
    rec["utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return rec


def mismatched(rec):
    return rec["outcome"] != "ERROR" and (
        rec["model_returned"] != rec["model_requested"] or rec["fallback_blocks"]
    )


def stops_run(rec):
    status = (rec["error"] or {}).get("status")
    return status in STOP_STATUSES


# ---- summaries ------------------------------------------------------------


def public_call(rec):
    usage = rec["usage"] or {}
    details = rec["stop_details"] or {}
    error = rec["error"] or {}
    return {
        "task_id": rec["task_id"],
        "repeat": rec["repeat"],
        "model_requested": rec["model_requested"],
        "model_returned": rec["model_returned"],
        "stop_reason": rec["stop_reason"],
        "stop_category": details.get("category"),
        "outcome": rec["outcome"],
        "error_status": error.get("status"),
        "error_type": error.get("error_type"),
        "attempts": rec["attempts"],
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "thinking_tokens": usage.get("thinking_tokens"),
        "utc_date": rec["utc"][:10],
        "prompt_sha256": rec["prompt_sha256"],
        "system_sha256": rec["system_sha256"],
        "output_sha256": rec["output_sha256"],
    }


def counts_table(calls):
    counts = {}
    for c in calls:
        key = (c["task_id"], c["model_requested"])
        row = counts.setdefault(key, dict.fromkeys(OUTCOMES, 0))
        row[c["outcome"]] += 1
    return counts


def format_counts(counts):
    lines = ["task  model  " + "  ".join(OUTCOMES)]
    for (task, model), row in sorted(counts.items()):
        lines.append(f"{task}  {model}  " + "  ".join(str(row[o]) for o in OUTCOMES))
    return "\n".join(lines)


def token_totals(calls):
    inp = sum(c["input_tokens"] or 0 for c in calls)
    out = sum(c["output_tokens"] or 0 for c in calls)
    cost = round((inp * PRICE_INPUT + out * PRICE_OUTPUT) / 1_000_000, 6)
    return {"input_tokens": inp, "output_tokens": out, "cost_usd": cost}


def write_public(public_root, run_id, args, sdk_version, calls, round_seconds):
    public_root.mkdir(parents=True, exist_ok=True)
    counts = counts_table(calls)
    totals = token_totals(calls)
    summary = {
        "run_id": run_id,
        "note": ONE_KEY_SENTENCE,
        "sdk_version": sdk_version,
        "effort": args.effort,
        "max_tokens": args.max_tokens,
        "concurrency": args.concurrency,
        "repeats": args.repeats,
        "round_seconds": round_seconds,
        "price_per_million_usd": {"input": PRICE_INPUT, "output": PRICE_OUTPUT},
        "calls": calls,
        "counts": [
            {"task_id": t, "model": m, **row} for (t, m), row in sorted(counts.items())
        ],
        "totals": totals,
    }
    (public_root / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    md = [
        f"# Model comparison summary, run {run_id}",
        "",
        ONE_KEY_SENTENCE,
        "",
        f"effort={args.effort}, max_tokens={args.max_tokens}, "
        f"repeats={args.repeats}, concurrency={args.concurrency}, sdk={sdk_version}",
        "",
        "| Task | Model | " + " | ".join(OUTCOMES) + " |",
        "|---|---|" + "---|" * len(OUTCOMES),
    ]
    for (task, model), row in sorted(counts.items()):
        md.append(f"| {task} | {model} | " + " | ".join(str(row[o]) for o in OUTCOMES) + " |")
    md += [
        "",
        "Round wall time (seconds): "
        + ", ".join(f"{i}: {t}" for i, t in enumerate(round_seconds, 1)),
        "",
        f"Tokens: input {totals['input_tokens']}, output {totals['output_tokens']}.",
        f"Cost at ${PRICE_INPUT:g} per million input tokens and "
        f"${PRICE_OUTPUT:g} per million output tokens: ${totals['cost_usd']:.4f}.",
        "",
    ]
    (public_root / "summary.md").write_text("\n".join(md))


# ---- dry run and main -----------------------------------------------------


def dry_run(system, prompts, tasks, models, args):
    requests = [
        (task, repeat, build_request(model, system, prompts[task], args))
        for repeat in range(1, args.repeats + 1)
        for task in tasks
        for model in models
    ]
    print(f"system.md sha256 {sha256(system)}")
    bound = 0.0
    for task, repeat, req in requests:
        prompt = req["messages"][0]["content"]
        print(f"{task} #{repeat} {req['model']} prompt sha256 {sha256(prompt)} "
              f"bytes {len(prompt.encode('utf-8'))}")
        est_in = (len(req["system"]) + len(prompt)) / 3.5
        bound += est_in * PRICE_INPUT / 1e6 + req["max_tokens"] * PRICE_OUTPUT / 1e6
    print(f"settings: effort={args.effort} max_tokens={args.max_tokens} "
          f"repeats={args.repeats} concurrency={args.concurrency}")
    print(f"calls: {len(requests)} in {args.repeats} rounds (none sent)")
    print(f"output-token bound: {len(requests) * args.max_tokens}")
    print(f"worst-case cost bound: ${bound:.2f}")
    return 0


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--models", default=DEFAULT_MODELS)
    p.add_argument("--tasks", default=DEFAULT_TASKS)
    p.add_argument("--repeats", type=int, default=10)
    p.add_argument("--effort", default="high")
    p.add_argument("--max-tokens", type=int, default=16000)
    p.add_argument("--concurrency", type=int, default=MAX_CONCURRENCY)
    p.add_argument("--run", action="store_true")
    p.add_argument("--access-note", default=None)
    return p.parse_args(argv)


def main(argv=None, client=None, private_root=PRIVATE, public_root=PUBLIC,
         prompts_dir=PROMPTS, expected_path=EXPECTED):
    args = parse_args(argv)
    models = [m for m in args.models.split(",") if m]
    tasks = [t for t in args.tasks.split(",") if t]
    system, prompts = load_prompts(prompts_dir)
    unknown = [t for t in tasks if t not in prompts or t not in CHECKS]
    if unknown:
        print(f"ERROR: unknown tasks: {unknown}")
        return 2
    if not args.run:
        return dry_run(system, prompts, tasks, models, args)
    if args.access_note is None:
        print("ERROR: --run needs --access-note")
        return 2
    if utc_today() > LAST_KEY_DAY:
        print(KEY_END_MESSAGE)
        return 2
    if client is None and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: missing ANTHROPIC_API_KEY")
        return 2

    import anthropic

    expected = json.loads(Path(expected_path).read_text())
    if client is None:
        # The SDK reads ANTHROPIC_API_KEY itself. The SDK retries stay off;
        # run_call retries by its own rule.
        client = anthropic.Anthropic(max_retries=0, timeout=600.0)

    sdk_version = anthropic.__version__
    start = datetime.now(timezone.utc)
    run_id = start.strftime("%Y%m%dT%H%M%SZ")
    args.concurrency = max(1, min(args.concurrency, MAX_CONCURRENCY))
    abort = threading.Event()

    def guarded(spec):
        if abort.is_set():
            return None
        rec = run_call(client, spec, system, args, expected)
        if mismatched(rec) or stops_run(rec):
            abort.set()
        return rec

    records, round_seconds = [], []
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for repeat in range(1, args.repeats + 1):
            specs = [(t, m, repeat, prompts[t]) for t in tasks for m in models]
            began = time.monotonic()
            batch = [r for r in pool.map(guarded, specs) if r is not None]
            seconds = round(time.monotonic() - began, 1)
            round_seconds.append(seconds)
            records += batch
            print(f"round {repeat}: {seconds}s", flush=True)
            if abort.is_set():
                break
            if repeat == 1 and any(r["outcome"] == "ERROR" for r in batch):
                break

    run_dir = Path(private_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    for rec in records:
        name = f"{rec['task_id']}-{rec['model_requested']}-{rec['repeat']}.json"
        (run_dir / name).write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
    (run_dir / "run.json").write_text(json.dumps({
        "run_id": run_id,
        "models": models, "tasks": tasks, "repeats": args.repeats,
        "effort": args.effort, "max_tokens": args.max_tokens,
        "concurrency": args.concurrency, "round_seconds": round_seconds,
        "access_note": args.access_note, "sdk_version": sdk_version,
        "start_utc": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2, sort_keys=True) + "\n")

    calls = [public_call(r) for r in records]
    write_public(Path(public_root), run_id, args, sdk_version, calls, round_seconds)

    for call in calls:
        extra = ""
        if call["outcome"] == "REFUSED":
            extra = f" ({call['stop_category']})"
        elif call["outcome"] == "ERROR":
            extra = f" ({call['error_status']} {call['error_type']})"
        print(f"{call['task_id']} {call['model_requested']} #{call['repeat']}: "
              f"{call['outcome']}{extra} stop={call['stop_reason']} "
              f"model={call['model_returned']} in={call['input_tokens']} "
              f"out={call['output_tokens']}")
    print(format_counts(counts_table(calls)))

    if any(mismatched(r) for r in records):
        print("MODEL MISMATCH or fallback block: run stopped")
        return 3
    if any(r["outcome"] == "ERROR" for r in records):
        print("ERROR: at least one call ended in ERROR")
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
