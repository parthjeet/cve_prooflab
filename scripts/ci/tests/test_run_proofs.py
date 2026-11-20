import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "run_proofs.sh"

# Fake docker. It logs its arguments and answers by the kind of call:
#   "run -d"          the app start; exits STUB_START_RC (default 0)
#   "READY_URL"       the readiness check; exits 0
#   "/proofs/test_proof_<n>.py"  a proof run; exits the code in $STUB_CODES/<n>
#                     (default 0); sleeps STUB_SLEEP seconds first, if set
#   "rm -f"           the cleanup; always exits 0
STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$*" in
  "rm -f"*) exit 0 ;;
  "run -d"*) exit "${STUB_START_RC:-0}" ;;
  *READY_URL*) exit 0 ;;
  */proofs/test_proof_*)
    all="$*"
    n="${all##*/proofs/test_proof_}"
    n="${n%%.py*}"
    [ "${STUB_SLEEP_FOR:-}" = "$n" ] && sleep "$STUB_SLEEP"
    if [ -f "$STUB_CODES/$n" ]; then exit "$(cat "$STUB_CODES/$n")"; fi
    exit 0 ;;
esac
exit 0
"""


@pytest.fixture
def ctx(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(STUB)
    docker.chmod(0o755)
    proofs = tmp_path / "proofs"
    proofs.mkdir()
    codes = tmp_path / "codes"
    codes.mkdir()
    e = dict(os.environ)
    e.update(
        PATH=f"{bindir}:{e['PATH']}",
        STUB_LOG=str(tmp_path / "docker.log"),
        STUB_CODES=str(codes),
        APP_IMAGE="app:test",
        RUNNER_IMAGE="runner:test",
        APP_PORT="8000",
        APP_READY_PATH="/status",
    )
    return e, proofs, codes, tmp_path


def make(proofs, *names):
    for name in names:
        (proofs / name).write_text("def test_x():\n    pass\n")


def run(ctx):
    e, proofs, _, tmp = ctx
    out = tmp / "out.json"
    r = subprocess.run(
        [str(SCRIPT), str(proofs), str(out)], env=e, capture_output=True, text=True
    )
    return r, out


def calls(ctx):
    log = Path(ctx[0]["STUB_LOG"])
    return log.read_text().splitlines() if log.exists() else []


def proof_calls(ctx):
    return [c for c in calls(ctx) if "/proofs/test_proof_" in c]


@pytest.mark.parametrize(
    "code,outcome",
    [(0, "confirmed"), (1, "not_confirmed"), (2, "error"), (5, "error"), (124, "error"), (137, "error")],
)
def test_exit_code_mapping(ctx, code, outcome):
    make(ctx[1], "test_proof_1.py")
    (ctx[2] / "1").write_text(str(code))
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == [f"proof 1: {outcome}"]
    assert json.loads(out.read_text()) == {"results": [{"n": 1, "outcome": outcome}]}


def test_real_timeout_gives_error(ctx):
    make(ctx[1], "test_proof_1.py")
    ctx[0]["STUB_SLEEP"] = "5"
    ctx[0]["STUB_SLEEP_FOR"] = "1"
    ctx[0]["PROOF_TIMEOUT"] = "1"
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text()) == {"results": [{"n": 1, "outcome": "error"}]}


def test_timeout_removes_test_container_before_next_test(ctx):
    make(ctx[1], "test_proof_1.py", "test_proof_2.py")
    ctx[0]["STUB_SLEEP"] = "5"
    ctx[0]["STUB_SLEEP_FOR"] = "1"
    ctx[0]["PROOF_TIMEOUT"] = "1"
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["proof 1: error", "proof 2: confirmed"]
    c = calls(ctx)
    first = next(i for i, x in enumerate(c) if "/proofs/test_proof_1.py" in x)
    second = next(i for i, x in enumerate(c) if "/proofs/test_proof_2.py" in x)
    assert "--name proof_test_1 " in c[first]
    assert "--name proof_test_2 " in c[second]
    assert "rm -f proof_test_1" in c[first + 1 : second]


def test_clean_exit_codes_do_not_remove_test_container(ctx):
    make(ctx[1], "test_proof_1.py")
    (ctx[2] / "1").write_text("1")
    run(ctx)
    # Only the exit trap removes it.
    assert calls(ctx).count("rm -f proof_test_1") == 1


def test_exit_trap_removes_test_containers(ctx):
    make(ctx[1], "test_proof_1.py")
    run(ctx)
    assert calls(ctx)[-2:] == ["rm -f proof_test_1", "rm -f proof_app"]


def test_name_pattern_filters(ctx):
    make(
        ctx[1],
        "x.py",
        "test_proof_1;id.py",
        "test_proof_1.py;id",
        "test_proof_a.py",
        "test_proof_.py",
        "test_proof_2.pyc",
        "xtest_proof_3.py",
        "test_proof_4.py",
    )
    (ctx[1] / "test_proof_5.py").mkdir()
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["proof 4: confirmed"]
    assert json.loads(out.read_text()) == {"results": [{"n": 4, "outcome": "confirmed"}]}
    assert len(proof_calls(ctx)) == 1


def test_numeric_order(ctx):
    make(ctx[1], "test_proof_10.py", "test_proof_2.py", "test_proof_1.py")
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["proof 1: confirmed", "proof 2: confirmed", "proof 10: confirmed"]
    assert [x["n"] for x in json.loads(out.read_text())["results"]] == [1, 2, 10]
    assert [c.split("/proofs/")[1].split(" ")[0] for c in proof_calls(ctx) if "-v" in c] == [
        "test_proof_1.py",
        "test_proof_2.py",
        "test_proof_10.py",
    ]


def test_app_start_failure_gives_error_for_all(ctx):
    make(ctx[1], "test_proof_1.py", "test_proof_2.py")
    ctx[0]["STUB_START_RC"] = "1"
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["proof 1: error", "proof 2: error"]
    assert json.loads(out.read_text()) == {
        "results": [{"n": 1, "outcome": "error"}, {"n": 2, "outcome": "error"}]
    }
    assert proof_calls(ctx) == []


def test_app_removed_on_exit(ctx):
    make(ctx[1], "test_proof_1.py")
    run(ctx)
    assert calls(ctx)[-1] == "rm -f proof_app"


def test_locked_down_flags(ctx):
    make(ctx[1], "test_proof_1.py")
    run(ctx)
    start = next(c for c in calls(ctx) if c.startswith("run -d"))
    for flag in ("--name proof_app", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges", "app:test"):
        assert flag in start
    test_call = proof_calls(ctx)[0]
    for flag in (
        "--network container:proof_app",
        "--read-only",
        "--tmpfs /tmp",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65534:65534",
        "--pids-limit 128",
        "--memory 512m",
        "--cpus 1",
        "PROOF_BASE_URL=http://127.0.0.1:8000",
        ":/proofs:ro",
        "runner:test python -m pytest /proofs/test_proof_1.py -q -p no:cacheprovider",
    ):
        assert flag in test_call


def test_missing_dir_gives_empty_results(ctx):
    ctx[1].rmdir()
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text()) == {"results": []}
    assert calls(ctx) == ["rm -f proof_app"]


def test_never_reads_file_contents(ctx):
    make(ctx[1], "test_proof_1.py")
    (ctx[1] / "test_proof_1.py").chmod(0)
    r, out = run(ctx)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["results"] == [{"n": 1, "outcome": "confirmed"}]
