"""Deterministic part of the AI security gate: validate, configure, judge.

No network code. Standard library only. This module raises GateError
subclasses; the caller maps them to exit code 2 (ERROR).
Verdict codes: 0 PASS, 1 BLOCK.
"""
import fnmatch
import json
import os
import re
import subprocess
import tomllib
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

SEVERITIES = ("low", "medium", "high", "critical")  # ascending
CONFIDENCES = ("low", "medium", "high")  # ascending
EFFORTS = ("low", "medium", "high", "xhigh", "max")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
NOTICE_HEAD = ("NOTICE: the base commit has no gate config; "
               "suppressions in the change under review are ignored")

FINDING_TYPES = {
    "title": str, "severity": str, "confidence": str, "cwe": str,
    "file": str, "line": int, "evidence": str, "impact": str, "fix": str,
}
INT_DEFAULTS = {
    "max_tokens": 16000, "max_tool_calls": 30, "max_requests": 20,
    "max_input_tokens": 400000, "max_output_tokens": 40000, "max_seconds": 600,
}
TRIAGE_TYPES = {
    "id": str, "package": str, "verdict": str, "confidence": str,
    "file": str, "line": int, "reason": str,
}
SCAN_TYPES = {"key": str, "verdict": str, "confidence": str, "reason": str}
VERDICTS = ("reachable", "not_reachable", "unknown")
SCAN_VERDICTS = ("true_positive", "false_positive", "unknown")
CLEAR_CONFIDENCE = "high"
SUPPRESS_KEYS = {"path", "id", "cwe", "reason", "expires"}


class GateError(Exception):
    pass


class InvalidAnswer(GateError):
    pass


class ConfigError(GateError):
    pass


@dataclass(frozen=True)
class Suppression:
    path: str | None
    cwe: str | None
    reason: str
    expires: date
    id: str | None = None


@dataclass(frozen=True)
class Config:
    fail_on: str = "high"
    min_confidence: str = "medium"
    effort: str = "medium"
    max_tokens: int = 16000
    max_tool_calls: int = 30
    max_requests: int = 20
    max_input_tokens: int = 400000
    max_output_tokens: int = 40000
    max_seconds: int = 600
    triage_min_severity: str = "high"
    suppressions: tuple[Suppression, ...] = ()


@dataclass(frozen=True)
class Verdict:
    code: int
    label: str
    blocking: list
    suppressed: list
    notes: list
    expired: list
    triage_blocking: list
    triage_cleared: list
    scan_blocking: list
    scan_cleared: list


@dataclass(frozen=True)
class Baseline:
    deps_open: list
    code_open: list
    accepted: list  # (kind, finding, suppression); kind is "dependency" or "code"
    expired: list


# ---- answer validation ----

def check_file(rel, line, head_root):
    """Raise InvalidAnswer unless rel is a regular file in head_root with `line` lines."""
    if not rel:
        raise InvalidAnswer("empty file")
    p = Path(rel)
    parts = p.parts
    if p.is_absolute() or ".." in parts or ".git" in parts:
        raise InvalidAnswer(f"file path not allowed: {rel!r}")
    root = os.path.realpath(head_root)
    real = os.path.realpath(os.path.join(root, rel))
    if os.path.commonpath([root, real]) != root:
        raise InvalidAnswer(f"file outside the checkout: {rel!r}")
    if ".git" in os.path.relpath(real, root).split(os.sep):
        raise InvalidAnswer(f"file inside .git: {rel!r}")
    if not os.path.isfile(real):
        raise InvalidAnswer(f"file is not a regular file: {rel!r}")
    with open(real, "rb") as f:
        count = len(f.read().splitlines())
    if line > count:
        raise InvalidAnswer(f"line {line} is past the end of {rel!r} ({count} lines)")


def check_finding(i, f, head_root):
    where = f"finding {i}"
    if not isinstance(f, dict):
        raise InvalidAnswer(f"{where} is not an object")
    missing = FINDING_TYPES.keys() - f.keys()
    extra = f.keys() - FINDING_TYPES.keys()
    if missing:
        raise InvalidAnswer(f"{where} is missing {sorted(missing)}")
    if extra:
        raise InvalidAnswer(f"{where} has extra keys {sorted(extra)}")
    for key, typ in FINDING_TYPES.items():
        v = f[key]
        if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
            raise InvalidAnswer(f"{where}: {key} must be {typ.__name__}")
    if f["severity"] not in SEVERITIES:
        raise InvalidAnswer(f"{where}: bad severity {f['severity']!r}")
    if f["confidence"] not in CONFIDENCES:
        raise InvalidAnswer(f"{where}: bad confidence {f['confidence']!r}")
    if not CWE_RE.fullmatch(f["cwe"]):
        raise InvalidAnswer(f"{where}: bad cwe {f['cwe']!r}")
    if f["line"] < 1:
        raise InvalidAnswer(f"{where}: line must be >= 1")
    try:
        check_file(f["file"], f["line"], head_root)
    except InvalidAnswer as e:
        raise InvalidAnswer(f"{where}: {e}") from None


def check_triage_entry(i, t, head_root):
    where = f"triage {i}"
    if not isinstance(t, dict):
        raise InvalidAnswer(f"{where} is not an object")
    missing = TRIAGE_TYPES.keys() - t.keys()
    extra = t.keys() - TRIAGE_TYPES.keys()
    if missing:
        raise InvalidAnswer(f"{where} is missing {sorted(missing)}")
    if extra:
        raise InvalidAnswer(f"{where} has extra keys {sorted(extra)}")
    for key, typ in TRIAGE_TYPES.items():
        v = t[key]
        if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
            raise InvalidAnswer(f"{where}: {key} must be {typ.__name__}")
    if t["verdict"] not in VERDICTS:
        raise InvalidAnswer(f"{where}: bad verdict {t['verdict']!r}")
    if t["confidence"] not in CONFIDENCES:
        raise InvalidAnswer(f"{where}: bad confidence {t['confidence']!r}")
    if t["verdict"] != "reachable":
        return {**t, "file": "", "line": 0}
    if t["line"] < 1:
        raise InvalidAnswer(f"{where}: line must be >= 1")
    try:
        check_file(t["file"], t["line"], head_root)
    except InvalidAnswer as e:
        raise InvalidAnswer(f"{where}: {e}") from None
    return t


def check_scan_entry(i, e):
    where = f"scan {i}"
    if not isinstance(e, dict):
        raise InvalidAnswer(f"{where} is not an object")
    missing = SCAN_TYPES.keys() - e.keys()
    extra = e.keys() - SCAN_TYPES.keys()
    if missing:
        raise InvalidAnswer(f"{where} is missing {sorted(missing)}")
    if extra:
        raise InvalidAnswer(f"{where} has extra keys {sorted(extra)}")
    for key, typ in SCAN_TYPES.items():
        if not isinstance(e[key], typ):
            raise InvalidAnswer(f"{where}: {key} must be {typ.__name__}")
    if e["verdict"] not in SCAN_VERDICTS:
        raise InvalidAnswer(f"{where}: bad verdict {e['verdict']!r}")
    if e["confidence"] not in CONFIDENCES:
        raise InvalidAnswer(f"{where}: bad confidence {e['confidence']!r}")


def validate_answer(raw, head_root, triage_input=(), scan_input=()):
    """Return the parsed answer dict or raise InvalidAnswer."""
    if isinstance(raw, (str, bytes)):
        try:
            answer = json.loads(raw)
        except ValueError as e:
            raise InvalidAnswer(f"not valid JSON: {e}") from None
    else:
        answer = raw
    if not isinstance(answer, dict):
        raise InvalidAnswer("answer is not an object")
    if not isinstance(answer.get("summary"), str):
        raise InvalidAnswer("summary missing or not a string")
    findings = answer.get("findings")
    if not isinstance(findings, list):
        raise InvalidAnswer("findings missing or not a list")
    for i, f in enumerate(findings):
        check_finding(i, f, head_root)
    triage = answer.get("triage")
    if not isinstance(triage, list):
        raise InvalidAnswer("triage missing or not a list")
    checked = [check_triage_entry(i, t, head_root) for i, t in enumerate(triage)]
    want = sorted((v["VulnerabilityID"], v["PkgName"]) for v in triage_input)
    got = sorted((t["id"], t["package"]) for t in checked)
    if got != want:
        raise InvalidAnswer("triage must hold each scanner finding (id, package) exactly once")
    scan = answer.get("scan")
    if not isinstance(scan, list):
        raise InvalidAnswer("scan missing or not a list")
    for i, e in enumerate(scan):
        check_scan_entry(i, e)
    if sorted(e["key"] for e in scan) != sorted(f["key"] for f in scan_input):
        raise InvalidAnswer("scan must hold each code scanner finding key exactly once")
    return {**answer, "triage": checked, "scan": scan}


# ---- config ----

def parse_suppression(i, s):
    where = f"suppress[{i}]"
    if not isinstance(s, dict):
        raise ConfigError(f"{where} is not a table")
    unknown = s.keys() - SUPPRESS_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    if "path" not in s and "id" not in s:
        raise ConfigError(f"{where}: path or id is required")
    for key in ("path", "id"):
        if key in s and (not isinstance(s[key], str) or not s[key].strip()):
            raise ConfigError(f"{where}: {key} must be a non-empty string")
    v = s.get("reason")
    if not isinstance(v, str) or not v.strip():
        raise ConfigError(f"{where}: reason is required and must be a non-empty string")
    cwe = s.get("cwe")
    if cwe is not None and not (isinstance(cwe, str) and CWE_RE.fullmatch(cwe)):
        raise ConfigError(f"{where}: cwe must match CWE-<n>")
    if cwe is not None and "path" not in s:
        raise ConfigError(f"{where}: cwe needs path")
    exp = s.get("expires")
    if type(exp) is not date:
        raise ConfigError(f"{where}: expires is required and must be a TOML date")
    return Suppression(s.get("path"), cwe, s["reason"], exp, s.get("id"))


def parse_config(data):
    allowed = {"fail_on", "min_confidence", "effort", "triage_min_severity", "suppress", *INT_DEFAULTS}
    unknown = data.keys() - allowed
    if unknown:
        raise ConfigError(f"unknown keys {sorted(unknown)}")
    values = {}
    for key, choices in (("fail_on", SEVERITIES), ("min_confidence", CONFIDENCES),
                         ("effort", EFFORTS),
                         ("triage_min_severity", SEVERITIES)):
        if key in data:
            if not isinstance(data[key], str):
                raise ConfigError(f"{key} must be a string")
            if data[key] not in choices:
                raise ConfigError(f"{key} must be one of {list(choices)}")
            values[key] = data[key]
    for key in INT_DEFAULTS:
        if key in data:
            v = data[key]
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                raise ConfigError(f"{key} must be an integer > 0")
            values[key] = v
    entries = data.get("suppress", [])
    if not isinstance(entries, list):
        raise ConfigError("suppress must be an array of tables")
    sup = tuple(parse_suppression(i, s) for i, s in enumerate(entries))
    return Config(suppressions=sup, **values)


def run_git(repo_dir, *args):
    try:
        return subprocess.run(["git", "-C", str(repo_dir), *args],
                              capture_output=True, text=True, encoding="utf-8")
    except (OSError, ValueError) as e:
        raise ConfigError(f"git failed: {e}") from None


def git_show(repo_dir, rev, config_path):
    """Return file text, or None if the commit has no such file. Uses exit codes only."""
    if run_git(repo_dir, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").returncode:
        raise ConfigError(f"not a valid commit: {rev}")
    spec = f"{rev}:{config_path}"
    if run_git(repo_dir, "cat-file", "-e", spec).returncode:
        return None
    r = run_git(repo_dir, "show", spec)
    if r.returncode:
        raise ConfigError(f"git show {spec} failed: {r.stderr.strip()}")
    return r.stdout


def stricter(head_value, default_value, order):
    """The value that makes more findings block or go to triage (the lower one)."""
    return min(head_value, default_value, key=order.index)


def load_config(repo_dir, base, head, config_path=".ai-security-gate.toml"):
    """Return (Config, notice). Read from base. With no config at base, use the limits
    of head, drop its suppressions, and keep the stricter of head and the defaults."""
    text = git_show(repo_dir, base, config_path)
    from_head = text is None
    if from_head:
        text = git_show(repo_dir, head, config_path)
        if text is None:
            return Config(), None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML: {e}") from None
    config = parse_config(data)
    if not from_head:
        return config, None
    default = Config()
    return replace(
        config, suppressions=(),
        fail_on=stricter(config.fail_on, default.fail_on, SEVERITIES),
        min_confidence=stricter(config.min_confidence, default.min_confidence, CONFIDENCES),
        triage_min_severity=stricter(config.triage_min_severity, default.triage_min_severity,
                                     SEVERITIES)), NOTICE_HEAD


# ---- judge ----

def matches(s, finding):
    return (s.path is not None
            and fnmatch.fnmatchcase(finding["file"], s.path)
            and (s.cwe is None or s.cwe == finding["cwe"]))


def baseline(deps, code, config, today):
    """Apply live suppressions to scanner findings; key the open code findings S1, S2, ..."""
    live = [s for s in config.suppressions if today <= s.expires]
    expired = [s for s in config.suppressions if today > s.expires]

    def accepting(file, id_):
        return next((s for s in live
                     if s.cwe is None
                     and (s.path is None or fnmatch.fnmatchcase(file, s.path))
                     and (s.id is None or s.id == id_)), None)

    accepted, deps_open, code_open, seen = [], [], [], set()
    for v in deps:
        match = accepting(v["Target"], v["VulnerabilityID"])
        if match:
            accepted.append(("dependency", v, match))
            continue
        key = (v["VulnerabilityID"], v["PkgName"])
        if key not in seen:
            seen.add(key)
            deps_open.append(v)
    for f in code:
        match = accepting(f["file"], f["rule_id"])
        if match:
            accepted.append(("code", f, match))
        else:
            code_open.append({"key": f"S{len(code_open) + 1}", **f})
    return Baseline(deps_open, code_open, accepted, expired)


def judge(answer, changed_files, config, today):
    """Pure decision: PASS (0) or BLOCK (1)."""
    live = [s for s in config.suppressions if today <= s.expires]
    expired = [s for s in config.suppressions if today > s.expires]
    blocking, suppressed, notes = [], [], []
    for f in answer["findings"]:
        would_block = (SEVERITIES.index(f["severity"]) >= SEVERITIES.index(config.fail_on)
                       and CONFIDENCES.index(f["confidence"])
                       >= CONFIDENCES.index(config.min_confidence)
                       and f["file"] in changed_files)
        match = next((s for s in live if matches(s, f)), None)
        if not would_block:
            notes.append(f)
        elif match:
            suppressed.append((f, match))
        else:
            blocking.append(f)
    t_blocking, t_cleared, s_blocking, s_cleared = [], [], [], []
    for t in answer["triage"]:
        cleared = t["verdict"] == "not_reachable" and t["confidence"] == CLEAR_CONFIDENCE
        (t_cleared if cleared else t_blocking).append(t)
    for e in answer["scan"]:
        cleared = e["verdict"] == "false_positive" and e["confidence"] == CLEAR_CONFIDENCE
        (s_cleared if cleared else s_blocking).append(e)
    code = 1 if blocking or t_blocking or s_blocking else 0
    return Verdict(code, "BLOCK" if code else "PASS", blocking, suppressed, notes, expired,
                   t_blocking, t_cleared, s_blocking, s_cleared)
