import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "sticky_comment.sh"
MARKER = "<!-- test-report -->"

STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_LOG"
case "$*" in
  *--method*) ;;
  *) cat "$STUB_LIST" ;;
esac
"""


@pytest.fixture
def env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(STUB)
    gh.chmod(0o755)
    log = tmp_path / "gh.log"
    lst = tmp_path / "list.json"
    lst.write_text("[]")
    body = tmp_path / "body.md"
    body.write_text(MARKER + "\nhello\n")
    e = dict(os.environ)
    e.update(
        PATH=f"{bindir}:{e['PATH']}",
        STUB_LOG=str(log),
        STUB_LIST=str(lst),
        GH_TOKEN="x",
        REPO="o/r",
        PR_NUMBER="7",
    )
    return e, log, lst, body


def run(env, body):
    e, log, lst, _ = env
    return subprocess.run(
        [str(SCRIPT), str(body)], env=e, capture_output=True, text=True
    )


def calls(log):
    return log.read_text().splitlines() if log.exists() else []


def mutating(log):
    return [c for c in calls(log) if "--method" in c]


def test_no_comment_posts(env):
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1
    assert "--method POST" in m[0] and "repos/o/r/issues/7/comments" in m[0]


def test_bot_marker_comment_patches(env):
    env[2].write_text(
        json.dumps(
            [
                {"id": 1, "user": {"login": "someone"}, "body": "x"},
                {"id": 42, "user": {"login": "github-actions[bot]"}, "body": MARKER + "\nold"},
            ]
        )
    )
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1
    assert "--method PATCH" in m[0] and "repos/o/r/issues/comments/42" in m[0]


MARKER_A = "<!-- security-scan-report -->"
MARKER_B = "<!-- ai-security-gate-report -->"


def _bot(id_, marker):
    return {"id": id_, "user": {"login": "github-actions[bot]"}, "body": marker + "\nold"}


@pytest.mark.parametrize("marker,expected", [(MARKER_A, "issues/comments/11"), (MARKER_B, "issues/comments/22")])
def test_two_markers_patch_own_comment(env, marker, expected):
    env[2].write_text(json.dumps([_bot(11, MARKER_A), _bot(22, MARKER_B)]))
    env[3].write_text(marker + "\nnew\n")
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1
    assert "--method PATCH" in m[0] and expected in m[0]


def test_other_marker_only_posts(env):
    env[2].write_text(json.dumps([_bot(11, MARKER_A)]))
    env[3].write_text(MARKER_B + "\nnew\n")
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1
    assert "--method POST" in m[0] and "repos/o/r/issues/7/comments" in m[0]


def test_other_author_marker_comment_posts(env):
    env[2].write_text(
        json.dumps([{"id": 5, "user": {"login": "mallory"}, "body": MARKER + "\nfake"}])
    )
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1 and "--method POST" in m[0]


def test_multi_page_output(env):
    env[2].write_text(
        '[{"id": 1, "user": {"login": "a"}, "body": "x"}]\n'
        + json.dumps([{"id": 9, "user": {"login": "github-actions[bot]"}, "body": MARKER}])
    )
    r = run(env, env[3])
    assert r.returncode == 0, r.stderr
    m = mutating(env[1])
    assert len(m) == 1 and "issues/comments/9" in m[0]


def test_bad_pr_number_refused(env):
    env[0]["PR_NUMBER"] = "1;x"
    r = run(env, env[3])
    assert r.returncode != 0
    assert calls(env[1]) == []


def test_bad_repo_refused(env):
    env[0]["REPO"] = "o/r;x"
    r = run(env, env[3])
    assert r.returncode != 0
    assert calls(env[1]) == []


def test_missing_marker_refused(env):
    env[3].write_text("no marker here\n")
    r = run(env, env[3])
    assert r.returncode != 0
    assert calls(env[1]) == []


def test_missing_body_file_refused(env, tmp_path):
    r = run(env, tmp_path / "nope.md")
    assert r.returncode != 0
    assert calls(env[1]) == []
