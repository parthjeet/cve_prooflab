"""Read-only tools for the AI security reviewer, and their path confinement.

Every tool returns a string. A refused or failed call returns a string that
starts with "ERROR: " and never raises: the model reads the error as text.
All paths are repo-relative POSIX paths. Nothing here writes to the checkout.
"""
import fnmatch
import os
import subprocess
from pathlib import Path

MAX_READ_LINES = 400
MAX_SEARCH_HITS = 100
MAX_DIFF_BYTES = 100_000
BINARY_SNIFF_BYTES = 8000
GIT_TIMEOUT_SECONDS = 30


def _err(message):
    return f"ERROR: {message}"


class Toolbox:
    def __init__(self, root: Path, base: str, head: str):
        self.root = Path(root)
        self.real_root = os.path.realpath(self.root)
        self.base = base
        self.head = head

    # ---- path confinement -------------------------------------------------

    def _resolve(self, path, allow_root=False, must_exist=True):
        """Return (real path string, None) or (None, error string)."""
        if not isinstance(path, str):
            return None, _err("path must be a string")
        if "\0" in path:
            return None, _err("path contains a NUL byte")
        if path.startswith("/") or os.path.isabs(path):
            return None, _err("absolute paths are not allowed")
        parts = [p for p in path.split("/") if p not in ("", ".")]
        if ".." in parts:
            return None, _err("'..' segments are not allowed")
        if ".git" in parts:
            return None, _err("access to .git is not allowed")
        if not parts and not allow_root:
            return None, _err("path is empty")
        real = os.path.realpath(os.path.join(self.real_root, *parts))
        if real != self.real_root and not real.startswith(self.real_root + os.sep):
            return None, _err("path resolves outside the repository")
        if ".git" in os.path.relpath(real, self.real_root).split(os.sep):
            return None, _err("access to .git is not allowed")
        if must_exist and not os.path.lexists(real):
            return None, _err("no such file or directory")
        return real, None

    @staticmethod
    def _is_binary(real):
        with open(real, "rb") as f:
            return b"\0" in f.read(BINARY_SNIFF_BYTES)

    # ---- tools ------------------------------------------------------------

    def list_files(self, dir):
        real, err = self._resolve(dir, allow_root=True)
        if err:
            return err
        if not os.path.isdir(real):
            return _err("not a directory")
        try:
            lines = []
            with os.scandir(real) as it:
                for entry in it:
                    if entry.name == ".git":
                        continue
                    lines.append(entry.name + ("/" if entry.is_dir() else ""))
        except OSError as e:
            return _err(f"cannot list directory: {e.strerror}")
        return "\n".join(sorted(lines))

    def read_file(self, path, start_line, end_line):
        real, err = self._resolve(path)
        if err:
            return err
        if not os.path.isfile(real):
            return _err("not a regular file")
        if start_line < 1 or end_line < start_line:
            return _err("need 1 <= start_line <= end_line")
        try:
            if self._is_binary(real):
                return _err("binary file")
            with open(real, "rb") as f:
                text = f.read().decode("utf-8", errors="replace")
        except OSError as e:
            return _err(f"cannot read file: {e.strerror}")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        total = len(lines)
        if start_line > total:
            return _err(f"start_line {start_line} is past the end; file has {total} lines")
        end = min(end_line, total)
        cut = end - start_line + 1 > MAX_READ_LINES
        if cut:
            end = start_line + MAX_READ_LINES - 1
        out = [f"{n}\t{lines[n - 1]}" for n in range(start_line, end + 1)]
        if cut:
            out.append(f"[cut at {MAX_READ_LINES} lines; next start_line is {end + 1}]")
        return "\n".join(out)

    def search(self, text, path_glob="*"):
        if not isinstance(text, str) or text == "":
            return _err("text must be a non-empty string")
        if not isinstance(path_glob, str):
            return _err("path_glob must be a string")
        rels = []
        for dirpath, dirnames, filenames in os.walk(self.real_root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.real_root).replace(os.sep, "/")
                if fnmatch.fnmatchcase(rel, path_glob):
                    rels.append(rel)
        hits = []
        more = False
        for rel in sorted(rels):
            real, err = self._resolve(rel)
            if err or not os.path.isfile(real):
                continue
            try:
                if self._is_binary(real):
                    continue
                with open(real, "rb") as f:
                    content = f.read().decode("utf-8", errors="replace")
            except OSError:
                continue
            for number, line in enumerate(content.split("\n"), start=1):
                if text in line:
                    if len(hits) == MAX_SEARCH_HITS:
                        more = True
                        break
                    hits.append(f"{rel}:{number}: {line.rstrip(chr(13))}")
            if more:
                break
        if not hits:
            return "no matches"
        if more:
            hits.append(f"[more than {MAX_SEARCH_HITS} hits; output cut]")
        return "\n".join(hits)

    def file_diff(self, path):
        _, err = self._resolve(path, must_exist=False)
        if err:
            return err
        if self.base.startswith("-") or self.head.startswith("-"):
            return _err("invalid revision")
        rel = "/".join(p for p in path.split("/") if p not in ("", "."))
        try:
            proc = subprocess.run(
                ["git", "-C", str(self.root), "diff", "--no-ext-diff", "--no-textconv",
                 "--no-color", f"{self.base}...{self.head}", "--", rel],
                capture_output=True, timeout=GIT_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.SubprocessError) as e:
            return _err(f"git diff failed: {e}")
        if proc.returncode != 0:
            first = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
            return _err(f"git diff failed: {first[0] if first else proc.returncode}")
        if not proc.stdout:
            return _err("file is not in the change")
        out = proc.stdout[:MAX_DIFF_BYTES].decode("utf-8", errors="replace")
        if len(proc.stdout) > MAX_DIFF_BYTES:
            out += f"\n[diff cut at {MAX_DIFF_BYTES} bytes]"
        return out


# ---- tool definitions and dispatch ------------------------------------------

def _tool(name, description, properties, required):
    return {
        "name": name,
        "description": description,
        "input_schema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
        "strict": True,
    }


TOOL_DEFINITIONS = [
    _tool(
        "list_files",
        "List one directory (not recursive), one entry per line, sorted. "
        "Directories end with '/'. Use '' or '.' for the repository root. "
        "Paths are repo-relative. Read-only.",
        {"dir": {"type": "string", "description": "Repo-relative directory path."}},
        ["dir"],
    ),
    _tool(
        "read_file",
        f"Read lines start_line to end_line (1-based, inclusive) of a text file. "
        f"Each line starts with its number and a tab. At most {MAX_READ_LINES} lines "
        f"per call; a longer span is cut and the output says where to continue. "
        "Paths are repo-relative. Read-only.",
        {
            "path": {"type": "string", "description": "Repo-relative file path."},
            "start_line": {"type": "integer", "description": "First line, 1-based."},
            "end_line": {"type": "integer", "description": "Last line, inclusive."},
        },
        ["path", "start_line", "end_line"],
    ),
    _tool(
        "search",
        f"Search for a literal substring (not a regex) in text files. Output is "
        f"'path:line: text', sorted, at most {MAX_SEARCH_HITS} hits. "
        "Paths are repo-relative. Read-only.",
        {
            "text": {"type": "string", "description": "Literal text to find. Not empty."},
            "path_glob": {
                "type": "string",
                "description": "Glob on the repo-relative path, for example 'src/*.py'. "
                               "Use '*' for all files.",
            },
        },
        ["text", "path_glob"],
    ),
    _tool(
        "file_diff",
        f"Show the diff of one file between the base and head revisions. "
        f"At most {MAX_DIFF_BYTES} bytes; a longer diff is cut. "
        "The path is repo-relative. Read-only.",
        {"path": {"type": "string", "description": "Repo-relative file path."}},
        ["path"],
    ),
]

_SCHEMAS = {t["name"]: t["input_schema"] for t in TOOL_DEFINITIONS}
_PY_TYPES = {"string": str, "integer": int}


def dispatch(toolbox, name, input_dict):
    """Run one tool call. Return its text. Never raise."""
    try:
        schema = _SCHEMAS.get(name)
        if schema is None:
            return _err(f"unknown tool {name}")
        if not isinstance(input_dict, dict):
            return _err("bad input: arguments must be an object")
        required = set(schema["required"])
        missing = required - set(input_dict)
        extra = set(input_dict) - set(schema["properties"])
        if missing:
            return _err(f"bad input: missing {', '.join(sorted(missing))}")
        if extra:
            return _err(f"bad input: unexpected {', '.join(sorted(extra))}")
        for key, value in input_dict.items():
            expected = schema["properties"][key]["type"]
            if not isinstance(value, _PY_TYPES[expected]) or isinstance(value, bool):
                return _err(f"bad input: {key} must be {expected}")
        return getattr(toolbox, name)(**input_dict)
    except Exception as e:  # tool errors go back to the model as text
        return _err(f"tool failed: {e!r}")
