import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "pick_model.sh"
ALLOWED = [
    "claude-mythos-5-2",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "claude-fable-5-2",
]
DEFAULT = ALLOWED[0]


def entry(comment="", state="approved", login="parthjeet", envs=("cvp",)):
    return {
        "state": state,
        "comment": comment,
        "user": {"login": login},
        "environments": [{"name": n, "id": 1} for n in envs],
    }


def run(tmp_path, content, **overrides):
    f = tmp_path / "approvals.json"
    f.write_text(content if isinstance(content, str) else json.dumps(content))
    e = dict(os.environ)
    e.update(
        ENVIRONMENT="cvp",
        APPROVER="parthjeet",
        DEFAULT_MODEL=DEFAULT,
        ALLOWED_MODELS=" ".join(ALLOWED),
    )
    e.update(overrides)
    return subprocess.run([str(SCRIPT), str(f)], env=e, capture_output=True, text=True)


def ok(r):
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_empty_comment_gives_default(tmp_path):
    assert ok(run(tmp_path, [entry("")])) == DEFAULT


def test_blank_comment_gives_default(tmp_path):
    assert ok(run(tmp_path, [entry("  \n ")])) == DEFAULT


@pytest.mark.parametrize("model", ALLOWED)
def test_allowed_model_gives_itself(tmp_path, model):
    assert ok(run(tmp_path, [entry(model)])) == model


def test_whitespace_is_trimmed(tmp_path):
    assert ok(run(tmp_path, [entry("  claude-opus-5-5\n")])) == "claude-opus-5-5"


@pytest.mark.parametrize(
    "comment", ["claude-opus", "Claude-Opus-5-5", "claude-opus-5-5 x", "$(id)"]
)
def test_bad_comment_fails_and_is_not_printed(tmp_path, comment):
    r = run(tmp_path, [entry(comment)])
    assert r.returncode == 1
    assert r.stdout == ""
    # "claude-opus" is a substring of an allowed ID, so strip the fixed message first.
    stripped = r.stderr.replace(", ".join(ALLOWED), "").replace(DEFAULT, "")
    assert comment not in stripped
    assert r.stderr.startswith("ERROR:")
    assert len(r.stderr.strip().splitlines()) == 1
    for m in ALLOWED:
        assert m in r.stderr


def test_other_login_does_not_count(tmp_path):
    r = run(tmp_path, [entry("claude-opus-5-5", login="someone")])
    assert r.returncode == 1 and r.stdout == ""


def test_other_environment_does_not_count(tmp_path):
    r = run(tmp_path, [entry("claude-opus-5-5", envs=("other",))])
    assert r.returncode == 1 and r.stdout == ""


def test_rejected_state_does_not_count(tmp_path):
    r = run(tmp_path, [entry("claude-opus-5-5", state="rejected")])
    assert r.returncode == 1 and r.stdout == ""


def test_other_login_does_not_add_a_second_value(tmp_path):
    data = [entry("claude-opus-5-5"), entry("claude-sonnet-5-5", login="someone")]
    assert ok(run(tmp_path, data)) == "claude-opus-5-5"


@pytest.mark.parametrize(
    "content",
    [[entry("", state="rejected")], [], {"a": 1}, "not json {", ""],
)
def test_unusable_input_fails(tmp_path, content):
    r = run(tmp_path, content)
    assert r.returncode == 1
    assert r.stdout == ""
    assert r.stderr.startswith("ERROR:")


def test_empty_and_valid_comment_give_valid_model(tmp_path):
    assert ok(run(tmp_path, [entry(""), entry("claude-fable-5-2")])) == "claude-fable-5-2"


def test_same_model_twice(tmp_path):
    data = [entry("claude-fable-5-2"), entry(" claude-fable-5-2 ")]
    assert ok(run(tmp_path, data)) == "claude-fable-5-2"


def test_two_different_models_fail(tmp_path):
    r = run(tmp_path, [entry("claude-fable-5-2"), entry("claude-opus-5-5")])
    assert r.returncode == 1
    assert r.stdout == ""
    assert "different models" in r.stderr


def test_one_entry_with_several_environments_counts(tmp_path):
    data = [entry("claude-sonnet-5-5", envs=("review-x", "cvp", "other"))]
    assert ok(run(tmp_path, data)) == "claude-sonnet-5-5"


def test_missing_env_var_fails(tmp_path):
    r = run(tmp_path, [entry("")], DEFAULT_MODEL="")
    assert r.returncode != 0 and r.stdout == ""
