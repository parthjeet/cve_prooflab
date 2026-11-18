#!/usr/bin/env python3
"""Frozen model comparison ("run 1"): five defensive security tasks, sent with
identical prompts and settings to each model through the Messages API.

Run once, by hand, with your own key in ANTHROPIC_API_KEY:

    uv run --no-project --python 3.12 --with anthropic==2.10.0 \\
        scripts/compare_models.py --access-note "free text"

Add --dry-run first: it prints prompt hashes, the call count, and a worst-case
cost bound, and makes no client and no network call.

Outputs:
- docs/showcase-runs/<run_id>/ (private, gitignored): full records, model text.
- reports/showcase/summary.{json,md} (public): counts and token totals only.
  No model text, request ID, explanation, or access note goes there.

Calls go in rounds: round r sends every task x model cell once, with at most 4
calls in flight, and finishes before round r+1 starts. A refusal is never
retried. A connection error, HTTP 429, or 5xx is retried up to 3 times.

Exit: 0 done, 2 no key, 3 a response named another model or held a fallback
block (the run stops after that round), 4 a round-1 call ended in ERROR (the
run stops after round 1). All records are written first.
"""
import argparse
import ast
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "scripts" / "showcase" / "prompts"
PRIVATE = ROOT / "docs" / "showcase-runs"
PUBLIC = ROOT / "reports" / "showcase"

DEFAULT_MODELS = "claude-mythos-5-2,claude-fable-5-2"
DEFAULT_TASKS = "R1,R2,R3,R4,R5"
PRICE_INPUT = 8.0
PRICE_OUTPUT = 40.0
OUTCOMES = ("COMPLETED", "NOT_COMPLETED", "REFUSED", "TRUNCATED", "ERROR")
R2_IDS = {
    "CVE-2024-47874", "CVE-2025-54121", "CVE-2026-48710", "CVE-2026-48817",
    "CVE-2026-48818", "CVE-2026-54282", "CVE-2026-54283",
}
R5_CVES = {"CVE-2023-29159", "CVE-2026-48817"}
R5_LINES = 40
RETRY_DELAYS = (2, 5, 10)  # seconds before retry 1, 2, 3
MAX_CONCURRENCY = 4


# ---- helpers --------------------------------------------------------------


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clean(text):
    """Remove the key from any text before it is stored or printed."""
    text = "" if text is None else str(text)
    key = os.environ.get("ANTHROPIC_API_KEY")
    return text.replace(key, "[redacted]") if key else text


def load_prompts(prompts_dir):
    system = (prompts_dir / "system.md").read_text()
    tasks = {p.stem: p.read_text() for p in sorted(prompts_dir.glob("R[0-9].md"))}
    return system, tasks


def prompt_ids(prompt):
    """Vulnerability IDs listed in the JSON input of a prompt, in order."""
    seen = []
    for found in re.findall(r'"VulnerabilityID": "(CVE-[0-9-]+)"', prompt):
        if found not in seen:
            seen.append(found)
    return seen


# ---- structure checks -----------------------------------------------------


def parse_json(text):
    text = text.strip()
    match = re.fullmatch(r"```json\s*\n(.*)\n```", text, re.DOTALL)
    if match:
        text = match.group(1)
    return json.loads(text)


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


def _check_id_list(data, key, expected, field, allowed):
    items = data.get(key)
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        return False, f"{key} is not a list of objects"
    ids = [i.get("id") for i in items]
    if sorted(map(str, ids)) != sorted(expected):
        return False, f"ids differ: got {sorted(map(str, ids))}"
    bad = [i.get("id") for i in items if i.get(field) not in allowed]
    if bad:
        return False, f"bad {field} for {bad}"
    return True, "ok"


def check_r1(text, prompt):
    data, err = _json_obj(text)
    if err:
        return False, err
    return _check_id_list(
        data, "findings", prompt_ids(prompt), "verdict",
        ("act_now", "act_soon", "monitor"),
    )


def check_r2(text, prompt):
    data, err = _json_obj(text)
    if err:
        return False, err
    return _check_id_list(
        data, "advisories", sorted(R2_IDS), "reachable", ("yes", "no", "unknown")
    )


def check_validation(text, prompt):
    if text.count("```python") != 1:
        return False, "not exactly one python block"
    match = re.search(r"```python\n(.*?)```", text, re.DOTALL)
    if not match:
        return False, "python block not closed"
    try:
        ast.parse(match.group(1))
    except SyntaxError as exc:
        return False, f"python block does not parse: {exc.msg}"
    if not re.search(r"^Meaning:", text, re.MULTILINE):
        return False, 'no line starting with "Meaning:"'
    return True, "ok"


def check_r5(text, prompt):
    data, err = _json_obj(text)
    if err:
        return False, err
    incidents, rules = data.get("incidents"), data.get("rules")
    if not isinstance(incidents, list) or not isinstance(rules, list):
        return False, "incidents or rules missing or not a list"
    for item in incidents:
        if not isinstance(item, dict):
            return False, "incident is not an object"
        if not _is_int(item.get("line")) or not 1 <= item["line"] <= R5_LINES:
            return False, f"bad line {item.get('line')!r}"
        if item.get("cve") not in R5_CVES:
            return False, f"bad cve {item.get('cve')!r}"
        if not isinstance(item.get("succeeded"), bool):
            return False, "succeeded is not a boolean"
    for item in rules:
        if not isinstance(item, dict) or not isinstance(item.get("regex"), str):
            return False, "rule without a regex string"
        try:
            re.compile(item["regex"])
        except re.error as exc:
            return False, f"regex does not compile: {exc}"
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


def classify(resp, task, prompt):
    """Return (outcome, check detail) for a response."""
    reason = resp.stop_reason
    if reason == "refusal":
        return "REFUSED", "refusal"
    if reason == "max_tokens":
        return "TRUNCATED", "max_tokens"
    text = "".join(b.text for b in resp.content if b.type == "text")
    if reason != "end_turn":
        return "NOT_COMPLETED", f"unexpected stop_reason {reason}"
    ok, detail = CHECKS[task](text, prompt)
    return ("COMPLETED" if ok else "NOT_COMPLETED"), detail


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


def run_call(client, spec, system, args):
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
        rec["outcome"], rec["check_detail"] = classify(resp, task, prompt)
    rec["utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return rec


# ---- summaries ------------------------------------------------------------


def public_call(rec, run_id, args, sdk_version):
    usage = rec["usage"] or {}
    details = rec["stop_details"] or {}
    error = rec["error"] or {}
    return {
        "run_id": run_id,
        "task_id": rec["task_id"],
        "repeat": rec["repeat"],
        "model_requested": rec["model_requested"],
        "model_returned": rec["model_returned"],
        "stop_reason": rec["stop_reason"],
        "stop_details_category": details.get("category"),
        "outcome": rec["outcome"],
        "error_status": error.get("status"),
        "error_type": error.get("error_type"),
        "attempts": rec["attempts"],
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "thinking_tokens": usage.get("thinking_tokens"),
        "prompt_sha256": rec["prompt_sha256"],
        "system_sha256": rec["system_sha256"],
        "output_sha256": rec["output_sha256"],
        "output_chars": rec["output_chars"],
        "utc": rec["utc"],
        "effort": args.effort,
        "max_tokens": args.max_tokens,
        "sdk_version": sdk_version,
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


def mismatched(rec):
    return rec["outcome"] != "ERROR" and (
        rec["model_returned"] != rec["model_requested"] or rec["fallback_blocks"]
    )


# ---- dry run and main -----------------------------------------------------


def dry_run(system, prompts, tasks, models, args):
    print(f"system.md sha256 {sha256(system)}")
    for task in tasks:
        print(f"{task} sha256 {sha256(prompts[task])} chars {len(prompts[task])}")
    requests = [
        build_request(model, system, prompts[task], args)
        for _ in range(args.repeats)
        for task in tasks
        for model in models
    ]
    bound = 0.0
    for req in requests:
        est_in = (len(req["system"]) + len(req["messages"][0]["content"])) / 3.5
        bound += est_in * PRICE_INPUT / 1e6 + req["max_tokens"] * PRICE_OUTPUT / 1e6
    print(f"calls: {len(requests)} in {args.repeats} rounds (none sent)")
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
    p.add_argument("--access-note", default="")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


def main(argv=None, client=None, private_root=PRIVATE, public_root=PUBLIC,
         prompts_dir=PROMPTS):
    args = parse_args(argv)
    models = [m for m in args.models.split(",") if m]
    tasks = [t for t in args.tasks.split(",") if t]
    system, prompts = load_prompts(prompts_dir)
    unknown = [t for t in tasks if t not in prompts or t not in CHECKS]
    if unknown:
        print(f"unknown tasks: {unknown}")
        return 2
    if args.dry_run:
        return dry_run(system, prompts, tasks, models, args)

    import anthropic

    if client is None:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ERROR: no ANTHROPIC_API_KEY in the environment")
            return 2
        # The SDK reads ANTHROPIC_API_KEY itself. Retries off.
        client = anthropic.Anthropic(max_retries=0, timeout=600.0)

    sdk_version = anthropic.__version__
    start = datetime.now(timezone.utc)
    run_id = start.strftime("%Y%m%dT%H%M%SZ")
    args.concurrency = max(1, min(args.concurrency, MAX_CONCURRENCY))
    records, round_seconds, stop = [], [], None
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for repeat in range(1, args.repeats + 1):
            specs = [(t, m, repeat, prompts[t]) for t in tasks for m in models]
            began = time.monotonic()
            batch = list(pool.map(lambda s: run_call(client, s, system, args), specs))
            seconds = round(time.monotonic() - began, 1)
            round_seconds.append(seconds)
            records += batch
            print(f"round {repeat}: {seconds}s", flush=True)
            if any(mismatched(r) for r in batch):
                stop = 3
                break
            if repeat == 1 and any(r["outcome"] == "ERROR" for r in batch):
                stop = 4
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
        "stopped_with_code": stop, "access_note": args.access_note,
        "sdk_version": sdk_version,
        "start_utc": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2, sort_keys=True) + "\n")

    calls = [public_call(r, run_id, args, sdk_version) for r in records]
    write_public(Path(public_root), run_id, args, sdk_version, calls, round_seconds)

    for rec, call in zip(records, calls):
        extra = ""
        if rec["outcome"] == "REFUSED":
            extra = f" ({call['stop_details_category']})"
        elif rec["outcome"] == "ERROR":
            extra = f" ({call['error_status']} {call['error_type']})"
        print(f"{rec['task_id']} {rec['model_requested']} #{rec['repeat']}: "
              f"{rec['outcome']}{extra}")
    print(format_counts(counts_table(calls)))

    if stop == 3:
        print("MODEL MISMATCH or fallback block: run stopped after this round")
    elif stop == 4:
        print("round 1 had an ERROR: run stopped after round 1")
    return stop or 0

if __name__ == "__main__":
    sys.exit(main())
