"""Verdict for the model showcase CI job. Standard library only.

Usage: ci_verdict.py SUMMARY_JSON EXPECTED_MODEL
Exit 0 only when there is at least one call, every call is COMPLETED, and
every model_returned equals EXPECTED_MODEL. Exit 1 otherwise. Exit 2 when the
summary is missing or unreadable.
"""
import json
import sys


def main(argv):
    if len(argv) != 3:
        print("MODEL SHOWCASE: ERROR usage: ci_verdict.py SUMMARY_JSON MODEL")
        return 2
    path, model = argv[1], argv[2]
    try:
        with open(path, encoding="utf-8") as f:
            calls = json.load(f)["calls"]
        if not isinstance(calls, list):
            raise ValueError("calls is not a list")
        outcomes = [c["outcome"] for c in calls]
        returned = [c["model_returned"] for c in calls]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"MODEL SHOWCASE: ERROR cannot read summary ({type(exc).__name__})")
        return 2

    total = len(calls)
    done = outcomes.count("COMPLETED")
    refused = outcomes.count("REFUSED")
    other = total - done - refused
    print(f"MODEL SHOWCASE: {model} COMPLETED {done} of {total}, "
          f"REFUSED {refused}, OTHER {other}")
    ok = total > 0 and done == total and all(r == model for r in returned)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
