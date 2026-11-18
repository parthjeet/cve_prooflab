import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools  # noqa: E402
from tools import TOOL_DEFINITIONS, Toolbox, dispatch  # noqa: E402


def git(root, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(root), *args],
                   check=True, capture_output=True)


@pytest.fixture
def box(tmp_path):
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    git(root, "init", "-q")
    (root / "a.txt").write_text("one\ntwo\nthree\n")
    (root / "sub" / "b.py").write_text("print('hi')\n")
    (root / "same.txt").write_text("unchanged\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    git(root, "tag", "base")
    (root / "a.txt").write_text("one\nTWO\nthree\n")
    (root / "lines.txt").write_text("".join(f"row {n}\n" for n in range(1, 1001)))
    (root / "hits.txt").write_text("needle\n" * 150)
    (root / "bigdiff.txt").write_text("".join(f"{n:05d} " + "x" * 40 + "\n" for n in range(4000)))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "head")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret\n")
    (root / "sub" / ".git").mkdir()
    (root / "sub" / ".git" / "x").write_text("secret\n")
    (root / "bin.dat").write_bytes(b"needle\0\x01\x02")
    os.symlink(outside / "secret.txt", root / "link_file")
    os.symlink(outside, root / "link_dir")
    return Toolbox(root, "base", "HEAD")


def is_err(s):
    return s.startswith("ERROR: ")


def test_list_files(box):
    out = box.list_files("")
    assert box.list_files(".") == out
    entries = out.split("\n")
    assert entries == sorted(entries)
    assert "sub/" in entries and "a.txt" in entries
    assert ".git" not in entries and ".git/" not in entries
    assert box.list_files("sub") == "b.py"


def test_read_file_normal(box):
    assert box.read_file("a.txt", 1, 2) == "1\tone\n2\tTWO"
    assert box.read_file("sub/b.py", 1, 99) == "1\tprint('hi')"


def test_read_file_past_end(box):
    out = box.read_file("a.txt", 10, 12)
    assert is_err(out) and "3 lines" in out


def test_read_file_400_cut(box):
    out = box.read_file("lines.txt", 1, 1000).split("\n")
    assert len(out) == 401
    assert out[399] == "400\trow 400"
    assert "cut" in out[400] and "401" in out[400]
    assert "cut" not in box.read_file("lines.txt", 1, 400)


def test_read_file_binary_refused(box):
    assert is_err(box.read_file("bin.dat", 1, 5))


def test_search(box):
    out = box.search("TWO", "*.txt")
    assert out == "a.txt:2: TWO"
    assert box.search("print", "sub/*") == "sub/b.py:1: print('hi')"
    assert box.search(".*", "a.txt") == "no matches"
    assert is_err(box.search("", "*"))


def test_search_cuts_at_100_hits(box):
    out = box.search("needle", "hits.txt").split("\n")
    assert len(out) == 101
    assert out[0] == "hits.txt:1: needle" and out[99] == "hits.txt:100: needle"
    assert "cut" in out[100]


def test_search_skips_binary_symlinks_and_git(box):
    out = box.search("needle", "*")
    assert "bin.dat" not in out
    assert box.search("secret", "*") == "no matches"


def test_file_diff(box):
    out = box.file_diff("a.txt")
    assert "-two" in out and "+TWO" in out


def test_file_diff_unchanged_file(box):
    assert is_err(box.file_diff("same.txt"))


def test_file_diff_cut(box):
    out = box.file_diff("bigdiff.txt")
    assert out.endswith("[diff cut at 100000 bytes]")
    assert len(out.encode()) < 100_000 + 100


@pytest.mark.parametrize("path", ["../x", "a/../../x", "sub/../a.txt", "/etc/passwd"])
def test_traversal_and_absolute_refused(box, path):
    assert is_err(box.read_file(path, 1, 1))
    assert is_err(box.list_files(path))
    assert is_err(box.file_diff(path))


def test_symlink_file_outside_refused(box):
    assert is_err(box.read_file("link_file", 1, 1))
    assert is_err(box.file_diff("link_file"))


def test_symlink_dir_outside_refused(box):
    assert is_err(box.list_files("link_dir"))
    assert is_err(box.read_file("link_dir/secret.txt", 1, 1))
    assert is_err(box.file_diff("link_dir/secret.txt"))


@pytest.mark.parametrize("path", [".git/config", "sub/.git/x", ".git"])
def test_git_dir_refused(box, path):
    assert is_err(box.read_file(path, 1, 1))
    assert is_err(box.list_files(path))
    assert is_err(box.file_diff(path))


def test_missing_path(box):
    assert box.read_file("nope.txt", 1, 1) == "ERROR: no such file or directory"
    assert box.list_files("nope") == "ERROR: no such file or directory"


def test_dispatch_ok(box):
    assert dispatch(box, "read_file", {"path": "a.txt", "start_line": 1, "end_line": 1}) == "1\tone"
    assert dispatch(box, "search", {"text": "TWO", "path_glob": "a.txt"}) == "a.txt:2: TWO"


def test_dispatch_bad_calls(box):
    assert dispatch(box, "rm", {}) == "ERROR: unknown tool rm"
    for name, args in [
        ("read_file", {"path": "a.txt", "start_line": 1}),
        ("list_files", {"dir": "", "extra": 1}),
        ("read_file", {"path": "a.txt", "start_line": "1", "end_line": 2}),
        ("read_file", {"path": "a.txt", "start_line": True, "end_line": 2}),
        ("list_files", {"dir": 5}),
        ("list_files", ["x"]),
    ]:
        out = dispatch(box, name, args)
        assert out.startswith("ERROR: bad input: "), (name, args, out)


def test_tool_definitions():
    assert [t["name"] for t in TOOL_DEFINITIONS] == ["list_files", "read_file", "search", "file_diff"]
    for t in TOOL_DEFINITIONS:
        assert t["input_schema"]["additionalProperties"] is False
        assert t["strict"] is True
        assert set(t["input_schema"]["required"]) <= set(t["input_schema"]["properties"])
    assert tools.MAX_READ_LINES == 400
