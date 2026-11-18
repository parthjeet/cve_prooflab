#!/usr/bin/env python3
"""Validation gate: run the regression tests against each lab image in a local container.

Each image runs in a container bound to 127.0.0.1. The script runs the pytest tests
against it, removes the container on every exit path, and compares the results
with a fixed table.

Usage: validate.py
Exit: 0 all results match, 1 a result differs from the table, 2 broken run.
"""
import http.client
import os
import re
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_FILE = ROOT / "tests" / "test_regression.py"
VARIANTS = ("vulnerable", "patched")
DOCKER_TIMEOUT = 60
PYTEST_TIMEOUT = 120
READY_DEADLINE = 30
READY_INTERVAL = 0.5
READY_ATTEMPT_TIMEOUT = 2

SIBLING = "test_sibling_folder_is_not_served"
EXPECTED = {
    "test_public_file_is_served": {"vulnerable": "passed", "patched": "passed"},
    SIBLING: {"vulnerable": "failed", "patched": "passed"},
    "test_unrelated_folder_is_not_served": {"vulnerable": "passed", "patched": "passed"},
}
MARKER_STATUS = "200"
MARKER_BODY = "LAB-MARKER-SIBLING"

# Set when `docker rm -f` of a container this script created fails.
CLEANUP_FAILED = []


class BrokenRun(Exception):
    """The run cannot give a trustworthy result."""


def say(message):
    print(message, flush=True)


def image_tag(variant):
    return f"cve_prooflab:{variant}"


def container_name(variant):
    return f"cve_prooflab_validate_{variant}"


def docker(*args):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              timeout=DOCKER_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise BrokenRun(f"docker {' '.join(args)} timed out after {DOCKER_TIMEOUT} s")


def preflight():
    for variant in VARIANTS:
        image = docker("image", "inspect", image_tag(variant))
        if image.returncode != 0:
            raise BrokenRun(f"image missing; build it first: {image_tag(variant)}\n"
                            f"{image.stderr.strip()}")
        name = container_name(variant)
        if docker("container", "inspect", name).returncode == 0:
            raise BrokenRun(f"container {name} already exists (left by a killed run). "
                            f"Remove it with: docker rm -f {name}")


def wait_ready(port, name):
    start = time.monotonic()
    deadline = start + READY_DEADLINE
    attempts = 0
    while True:
        attempts += 1
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=READY_ATTEMPT_TIMEOUT)
            try:
                conn.request("GET", "/static/index.html")
                ready = conn.getresponse().status == 200
            finally:
                conn.close()
        except Exception:
            ready = False
        elapsed = time.monotonic() - start
        if ready:
            say(f"  ready after {attempts} attempts, {elapsed:.1f} s")
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(READY_INTERVAL, remaining))
    say(f"  not ready after {attempts} attempts, {elapsed:.1f} s")
    logs = docker("logs", name)
    say(f"  docker logs {name}:\n{logs.stdout}{logs.stderr}")
    raise BrokenRun(f"container {name} never answered 200 on /static/index.html")


def parse_junit(path):
    """Return a list of dicts: name, outcome, status, body (None if the property is missing)."""
    try:
        root = ET.parse(str(path)).getroot()
    except (OSError, ET.ParseError) as e:
        raise BrokenRun(f"cannot read JUnit XML {path}: {e}")
    results = []
    for case in root.iter("testcase"):
        tags = {child.tag for child in case}
        if "error" in tags:
            outcome = "error"
        elif "failure" in tags:
            outcome = "failed"
        elif "skipped" in tags:
            outcome = "skipped"
        else:
            outcome = "passed"
        props = {p.get("name"): p.get("value")
                 for p in case.findall("properties/property")}
        results.append({"name": case.get("name"), "outcome": outcome,
                        "status": props.get("status"), "body": props.get("body")})
    return results


def check_structure(results):
    """Raise BrokenRun unless the results hold exactly the three tests, each usable."""
    names = sorted(r["name"] or "" for r in results)
    if names != sorted(EXPECTED):
        raise BrokenRun(f"testcases are {names}, expected {sorted(EXPECTED)}")
    for r in results:
        if r["outcome"] in ("error", "skipped"):
            raise BrokenRun(f"{r['name']} has outcome {r['outcome']}")
        if r["status"] is None or r["body"] is None:
            raise BrokenRun(f"{r['name']} has no status or body property")


def judge(paths):
    """Compare both variants with the table. Return 0, 1 or 2."""
    broken = False
    mismatch = False
    for variant in VARIANTS:
        try:
            results = parse_junit(paths[variant])
            check_structure(results)
        except BrokenRun as e:
            say(f"{variant}: broken run: {e}")
            broken = True
            continue
        by_name = {r["name"]: r for r in results}
        for test, expected in EXPECTED.items():
            r = by_name[test]
            ok = r["outcome"] == expected[variant]
            mismatch |= not ok
            say(f"{variant} {test} {expected[variant]} {r['outcome']} {r['status']} "
                f"{'MATCH' if ok else 'MISMATCH'}")
        if variant == "vulnerable":
            r = by_name[SIBLING]
            ok = r["status"] == MARKER_STATUS and r["body"] == MARKER_BODY
            mismatch |= not ok
            say(f"{variant} {SIBLING} marker expected status {MARKER_STATUS} body "
                f"{MARKER_BODY!r} actual status {r['status']} body {r['body']!r} "
                f"{'MATCH' if ok else 'MISMATCH'}")
    return 2 if broken else 1 if mismatch else 0


def remove_container(name):
    old_int = signal.signal(signal.SIGINT, signal.SIG_IGN)
    old_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        try:
            rm = docker("rm", "-f", name)
            failed = rm.returncode != 0
            detail = rm.stderr.strip()
        except BrokenRun as e:
            failed, detail = True, str(e)
        if failed:
            say(f"clean-up failed for container {name}: {detail}")
            CLEANUP_FAILED.append(name)
    finally:
        signal.signal(signal.SIGINT, old_int)
        signal.signal(signal.SIGTERM, old_term)


def run_variant(variant):
    """Start the container, run pytest, remove the container. Return the XML path."""
    name = container_name(variant)
    xml_path = ROOT / "reports" / f"junit-{variant}.xml"
    attempted = False
    say(f"[{variant}]")
    try:
        attempted = True
        run = docker("run", "-d", "--name", name, "-p", "127.0.0.1::8000", image_tag(variant))
        if run.returncode != 0:
            raise BrokenRun(f"docker run failed:\n{run.stderr.strip()}")

        port_out = docker("port", name, "8000/tcp")
        if port_out.returncode != 0:
            raise BrokenRun(f"docker port failed:\n{port_out.stderr.strip()}")
        lines = port_out.stdout.splitlines()
        match = re.fullmatch(r"127\.0\.0\.1:(\d+)", lines[0]) if len(lines) == 1 else None
        if not match or not 1 <= int(match.group(1)) <= 65535:
            raise BrokenRun(f"docker port output {port_out.stdout!r} is not one line "
                            "127.0.0.1:<port>")
        port = int(match.group(1))
        say(f"  container {name} on 127.0.0.1:{port}")

        wait_ready(port, name)

        xml_path.unlink(missing_ok=True)
        env = {**os.environ, "LAB_BASE_URL": f"http://127.0.0.1:{port}"}
        cmd = [sys.executable, "-m", "pytest", str(TEST_FILE), f"--junitxml={xml_path}",
               "-p", "no:cacheprovider", "-q"]
        try:
            proc = subprocess.run(cmd, env=env, timeout=PYTEST_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise BrokenRun(f"pytest timed out after {PYTEST_TIMEOUT} s")
        if proc.returncode not in (0, 1):
            raise BrokenRun(f"pytest exited with code {proc.returncode}")
        if not xml_path.is_file():
            raise BrokenRun(f"pytest wrote no {xml_path}")

        check_structure(parse_junit(xml_path))
        return xml_path
    finally:
        if attempted:
            remove_container(name)


def on_sigterm(signum, frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, on_sigterm)
    code = 2
    try:
        preflight()
        paths = {}
        for variant in VARIANTS:
            paths[variant] = run_variant(variant)
            if CLEANUP_FAILED:
                raise BrokenRun(f"could not remove container {CLEANUP_FAILED[0]}")
        code = judge(paths)
    except BrokenRun as e:
        say(f"broken run: {e}")
    except (KeyboardInterrupt, SystemExit):
        say("interrupted")
    except Exception as e:  # an uncaught error must not read as a gate failure
        say(f"unexpected error: {e!r}")
    if CLEANUP_FAILED:
        code = 2
    return code


if __name__ == "__main__":
    result = main()
    say({0: "VALIDATION GATE: PASS", 1: "VALIDATION GATE: FAIL"}.get(result, "VALIDATION GATE: ERROR"))
    sys.exit(result)
