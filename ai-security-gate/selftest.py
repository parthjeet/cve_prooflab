#!/usr/bin/env python3
"""AI gate self-test: the review must return the expected verdict on fixed fixtures.

Usage: selftest.py [--evidence-dir DIR] [--model ID]
Exit: 0 all fixtures match, 1 a fixture does not match, 2 harness error.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "selftest" / "fixtures"

GIT = ["git", "-c", "user.name=selftest", "-c", "user.email=selftest@invalid",
       "-c", "commit.gpgsign=false"]


def git(repo, *args):
    done = subprocess.run(GIT + list(args), cwd=repo, check=True,
                          capture_output=True, text=True)
    return done.stdout.strip()


def build_repo(fixture_dir, work_dir):
    """Create a repo with base/ committed, then head/ committed. Return (path, base, head)."""
    fixture_dir, work_dir = Path(fixture_dir), Path(work_dir)
    repo = Path(tempfile.mkdtemp(prefix=fixture_dir.name + "-", dir=work_dir))
    git(repo, "init", "-q")
    shutil.copytree(fixture_dir / "base", repo, dirs_exist_ok=True, copy_function=shutil.copy)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    base_sha = git(repo, "rev-parse", "HEAD")

    for item in repo.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
    shutil.copytree(fixture_dir / "head", repo, dirs_exist_ok=True, copy_function=shutil.copy)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "head")
    head_sha = git(repo, "rev-parse", "HEAD")
    return repo, base_sha, head_sha


def check(expected, result):
    """Return (ok, reason) for one review result against one expected file."""
    verdict = result.get("verdict")
    if verdict == "ERROR":
        return False, "verdict ERROR"
    if verdict != expected["verdict"]:
        return False, f"expected verdict {expected['verdict']}, got {verdict}"
    blocking = result.get("blocking") or []
    for req in expected.get("require", []):
        if not any(f.get("file") == req["file"] and f.get("cwe") in req["cwe_any"]
                   for f in blocking):
            return False, f"no blocking finding for {req['file']} with CWE in {req['cwe_any']}"
    triage = result.get("triage") or []
    for vuln_id, want in (expected.get("triage") or {}).items():
        entries = [t for t in triage if t.get("id") == vuln_id]
        if len(entries) != 1:
            return False, f"{vuln_id}: expected one triage entry, got {len(entries)}"
        entry = entries[0]
        if entry.get("verdict") != want:
            return False, f"{vuln_id}: expected triage {want}, got {entry.get('verdict')}"
        if want == "reachable" and entry.get("ruling") != "blocking":
            return False, f"{vuln_id}: reachable but ruling is {entry.get('ruling')}, not blocking"
    scan = result.get("scan") or []
    for key, want in (expected.get("scan") or {}).items():
        file, _, line = key.rpartition(":")
        entries = [e for e in scan if e.get("file") == file and str(e.get("line")) == line]
        if len(entries) != 1:
            return False, f"{key}: expected one scan entry, got {len(entries)}"
        entry = entries[0]
        if entry.get("verdict") != want["verdict"]:
            return False, f"{key}: expected scan {want['verdict']}, got {entry.get('verdict')}"
        if entry.get("ruling") != want["ruling"]:
            return False, f"{key}: expected ruling {want['ruling']}, got {entry.get('ruling')}"
    return True, "ok"


def run(fixtures_root, review_fn, work_dir):
    """Run every fixture through review_fn. Return the exit code."""
    try:
        names = sorted(p.name for p in Path(fixtures_root).iterdir() if p.is_dir())
        if not names:
            raise ValueError(f"no fixtures in {fixtures_root}")
        outcomes = []
        for name in names:
            fixture = Path(fixtures_root) / name
            expected = json.loads((fixture / "expected.json").read_text(encoding="utf-8"))
            repo, base_sha, head_sha = build_repo(fixture, work_dir)
            report = fixture / "scanner-report.json"
            report = str(report) if report.exists() else None
            sarif = fixture / "scan.sarif"
            sarif_reports = (str(sarif),) if sarif.exists() else ()
            try:
                result = review_fn(repo, base_sha, head_sha, report, sarif_reports)
            except Exception as e:
                result = {"verdict": "ERROR", "blocking": [], "error": repr(e)}
            ok, reason = check(expected, result)
            print(f"{name}: MATCH" if ok else f"{name}: MISMATCH ({reason})")
            outcomes.append(ok)
    except Exception as e:  # a harness failure must not read as a gate failure
        print(f"harness error: {e!r}")
        print("AI GATE SELF-TEST: ERROR")
        return 2
    if all(outcomes):
        print("AI GATE SELF-TEST: PASS")
        return 0
    print("AI GATE SELF-TEST: FAIL")
    return 1


def token_line(evidence_dir):
    """Sum the totals of the evidence files in evidence_dir."""
    sums = {"total_input_tokens": 0, "output_tokens": 0, "requests": 0}
    for path in sorted(Path(evidence_dir).glob("*-evidence.json")):
        totals = json.loads(path.read_text(encoding="utf-8")).get("totals") or {}
        for key in sums:
            sums[key] += totals.get(key) or 0
    return (f"self-test tokens: input={sums['total_input_tokens']} "
            f"output={sums['output_tokens']} requests={sums['requests']}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="AI gate self-test")
    parser.add_argument("--evidence-dir", default=None,
                        help="write <fixture>-evidence.json and <fixture>-summary.json here")
    parser.add_argument("--model", default=None,
                        help="model ID passed to the review (default: the review's own default)")
    args = parser.parse_args(argv)

    from review import run_review

    extra = {"model": args.model} if args.model is not None else {}

    def review_fn(repo, base_sha, head_sha, scanner_report=None, sarif_reports=()):
        return run_review(repo, base_sha, head_sha, scanner_report, sarif_reports, **extra)

    if args.evidence_dir:
        evidence_dir = Path(args.evidence_dir)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        def review_fn(repo, base_sha, head_sha, scanner_report=None, sarif_reports=()):
            fixture = Path(repo).name.rsplit("-", 1)[0]
            return run_review(repo, base_sha, head_sha, scanner_report, sarif_reports,
                              evidence_path=evidence_dir / f"{fixture}-evidence.json",
                              summary_path=evidence_dir / f"{fixture}-summary.json", **extra)

    with tempfile.TemporaryDirectory() as work_dir:
        code = run(FIXTURES, review_fn, work_dir)
    if args.evidence_dir:
        print(token_line(args.evidence_dir))
    return code


if __name__ == "__main__":
    sys.exit(main())
