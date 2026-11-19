"""Markdown report of the model showcase CI summary. Standard library only.

Usage: ci_report.py SUMMARY_JSON [--run-url URL]
Exit 0 with markdown on standard output. Exit 2 with one line on standard
error and nothing on standard output when the file is missing, is not JSON,
or is not an object with a "calls" list.

Every string from the summary is untrusted. The report holds no model output,
no request ID, no access note, no price, and no cost.
"""
import argparse
import json
import re
import sys

MARKER = "<!-- model-showcase-report -->"
MAX_ROWS = 50
MAX_CHARS = 60000
CUT = 200
OUTCOMES = {"COMPLETED", "REFUSED", "TRUNCATED", "ERROR", "NOT_COMPLETED"}
STOP_REASONS = {"end_turn", "max_tokens", "refusal", "stop_sequence",
                "tool_use", "pause_turn"}
STOP_CATEGORIES = {"cyber"}
RUN_URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
                     r"/actions/runs/[0-9]+(/attempts/[0-9]+)?")
SHA = re.compile(r"[0-9a-f]{7,64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
SAFE = re.compile(r"[A-Za-z0-9 ._/-]")
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")


def _clean(value, limit):
    s = CONTROL.sub(" ", str(value))[:limit]
    return "".join(ch if SAFE.fullmatch(ch) else f"&#{ord(ch)};" for ch in s)


def code(value, limit=CUT):
    return f"<code>{_clean(value, limit)}</code>"


def text(value, limit=CUT):
    return _clean(value, limit).replace("&#64;", "(at)")


def enum(value, known):
    """Bare when in the known set, else through code. None prints as a dash."""
    if value is None:
        return "-"
    if isinstance(value, str) and value in known:
        return value
    return code(value)


def num(value):
    return str(value) if isinstance(value, int) and not isinstance(value, bool) else "-"


def sha(value):
    if isinstance(value, str) and SHA.fullmatch(value):
        return f"<code>{value}</code>"
    return "-"


def date(value):
    if isinstance(value, str) and DATE.fullmatch(value):
        return value
    return "-"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |",
           "|" + "---|" * len(header)]
    out += ["| " + " | ".join(r) + " |" for r in rows[:MAX_ROWS]]
    if len(rows) > MAX_ROWS:
        out.append("")
        out.append(f"and {len(rows) - MAX_ROWS} more; see the summary artifact")
    return out


def tally(items):
    """Counts of values, in order of first appearance, as 'value xN' pieces."""
    seen = {}
    for item in items:
        key = item if isinstance(item, (str, type(None))) else repr(item)
        seen[key] = seen.get(key, 0) + 1
    return seen


def render(summary, run_url=None):
    calls = [c if isinstance(c, dict) else {} for c in summary["calls"]]
    total = len(calls)
    done = sum(c.get("outcome") == "COMPLETED" for c in calls)
    refused = sum(c.get("outcome") == "REFUSED" for c in calls)
    other = total - done - refused

    models = {c.get("model_requested") for c in calls
              if isinstance(c.get("model_requested"), str)}
    if not calls:
        model = "no calls"
    elif len(models) == 1 and all(isinstance(c.get("model_requested"), str)
                                  for c in calls):
        model = code(next(iter(models)))
    else:
        model = "the calls name more than one model, or none"

    lines = [MARKER, "", f"## Model showcase: {model}", "",
             f"COMPLETED {done} of {total}, REFUSED {refused}, OTHER {other}", "",
             "COMPLETED means the output passed a structure check. "
             "No generated test was run.", ""]

    tasks = {}
    for c in calls:
        tid = c.get("task_id") if isinstance(c.get("task_id"), str) else None
        tasks.setdefault(tid, []).append(c)
    rows = []
    for tid, group in tasks.items():
        d = sum(c.get("outcome") == "COMPLETED" for c in group)
        r = sum(c.get("outcome") == "REFUSED" for c in group)
        reasons = ", ".join(f"{enum(k, STOP_REASONS)} x{n}" for k, n in
                            tally(c.get("stop_reason") for c in group).items())
        cats = ", ".join(f"{enum(k, STOP_CATEGORIES)} x{n}" for k, n in
                         tally(c.get("stop_category") for c in group).items())
        rows.append([code(tid) if tid is not None else "-", str(len(group)),
                     str(d), str(r), str(len(group) - d - r), reasons, cats])
    if rows:
        lines += table(["Task", "Calls", "COMPLETED", "REFUSED", "Other",
                        "Stop reasons", "Stop categories"], rows)
        lines.append("")

    if isinstance(run_url, str) and RUN_URL.fullmatch(run_url):
        lines += [f"[Workflow run]({run_url})", ""]

    lines += ["<details>", "<summary>Calls</summary>", ""]
    rows = []
    for c in calls:
        rows.append([
            code(c["task_id"]) if isinstance(c.get("task_id"), str) else "-",
            num(c.get("repeat")),
            code(c["model_requested"]) if isinstance(c.get("model_requested"), str) else "-",
            code(c["model_returned"]) if isinstance(c.get("model_returned"), str) else "-",
            enum(c.get("stop_reason"), STOP_REASONS),
            enum(c.get("stop_category"), STOP_CATEGORIES),
            enum(c.get("outcome"), OUTCOMES),
            num(c.get("input_tokens")), num(c.get("output_tokens")),
            date(c.get("utc_date"))])
    lines += table(["Task", "Repeat", "Requested", "Returned", "Stop reason",
                    "Stop category", "Outcome", "Input tokens",
                    "Output tokens", "Date"], rows)
    lines += ["", "</details>", "", "<details>", "<summary>Settings</summary>", ""]
    dates = sorted({c["utc_date"] for c in calls if date(c.get("utc_date")) != "-"})
    lines += [f"- Effort: {enum(summary.get('effort'), {'low', 'medium', 'high', 'max'})}",
              f"- max_tokens: {num(summary.get('max_tokens'))}",
              f"- Repeats: {num(summary.get('repeats'))}",
              f"- SDK version: {code(summary['sdk_version']) if isinstance(summary.get('sdk_version'), str) else '-'}",
              f"- Date: {', '.join(dates) if dates else '-'}"]
    prompts = {}
    for c in calls:
        if isinstance(c.get("task_id"), str):
            prompts.setdefault(c["task_id"], c.get("prompt_sha256"))
    for tid, h in list(prompts.items())[:MAX_ROWS]:
        lines.append(f"- prompt_sha256 of {code(tid)}: {sha(h)}")
    if len(prompts) > MAX_ROWS:
        lines.append(f"- and {len(prompts) - MAX_ROWS} more; see the summary artifact")
    lines += ["", "</details>", ""]

    out = "\n".join(lines)
    if len(out) > MAX_CHARS:
        out = out[:MAX_CHARS].rsplit("\n", 1)[0] + "\n\nReport cut at 60000 characters; see the summary artifact.\n"
    return out


def main(argv):
    p = argparse.ArgumentParser(prog="ci_report.py")
    p.add_argument("summary")
    p.add_argument("--run-url")
    args = p.parse_args(argv[1:])
    try:
        with open(args.summary, encoding="utf-8") as f:
            summary = json.load(f)
        if not isinstance(summary, dict) or not isinstance(summary.get("calls"), list):
            raise ValueError("not an object with a calls list")
    except (OSError, ValueError) as exc:
        print(f"ci_report: cannot read summary ({type(exc).__name__})", file=sys.stderr)
        return 2
    sys.stdout.write(render(summary, args.run_url))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
