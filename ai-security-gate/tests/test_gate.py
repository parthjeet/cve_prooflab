import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gate  # noqa: E402

TODAY = date(2026, 6, 1)


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
                   check=True, capture_output=True)


def commit(repo, files, msg="c"):
    for name, text in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-m", msg)
    out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         check=True, capture_output=True, text=True)
    return out.stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q")
    return r


def finding(**kw):
    f = {"title": "t", "severity": "high", "confidence": "high", "cwe": "CWE-22",
         "file": "app/a.py", "line": 1, "evidence": "e", "impact": "i", "fix": "f"}
    f.update(kw)
    return f


def answer(*findings, triage=(), scan=()):
    return {"summary": "s", "findings": list(findings), "triage": list(triage),
            "scan": list(scan)}


def sc(**kw):
    e = {"key": "S1", "verdict": "true_positive", "confidence": "high", "reason": "r"}
    e.update(kw)
    return e


def code_in(*keys):
    return [{"key": k} for k in keys]


def tri(**kw):
    t = {"id": "CVE-1", "package": "pkg", "verdict": "reachable", "confidence": "high",
         "file": "app/a.py", "line": 1, "reason": "r"}
    t.update(kw)
    return t


def scan(id="CVE-1", package="pkg", target="req.txt"):
    return {"VulnerabilityID": id, "PkgName": package, "Target": target}


def id_sup(id="CVE-1", expires=date(2027, 1, 1)):
    return gate.Suppression(None, None, "r", expires, id)


def cfg(**kw):
    return gate.Config(**kw)


def sup(path="app/*", cwe=None, expires=date(2027, 1, 1), reason="r"):
    return gate.Suppression(path, cwe, reason, expires)


# ---- judge ----

def test_zero_findings_pass():
    v = gate.judge(answer(), {"app/a.py"}, cfg(), TODAY)
    assert (v.code, v.label, v.blocking) == (0, "PASS", [])


@pytest.mark.parametrize("sev,blocks", [("critical", True), ("high", True),
                                         ("medium", False), ("low", False)])
def test_severity_threshold(sev, blocks):
    v = gate.judge(answer(finding(severity=sev)), {"app/a.py"}, cfg(fail_on="high"), TODAY)
    assert (v.code == 1) == blocks
    assert (len(v.notes) == 1) == (not blocks)


@pytest.mark.parametrize("conf,blocks", [("high", True), ("medium", True), ("low", False)])
def test_confidence_threshold(conf, blocks):
    v = gate.judge(answer(finding(confidence=conf)), {"app/a.py"},
                   cfg(min_confidence="medium"), TODAY)
    assert (v.code == 1) == blocks


def test_fail_on_low_blocks_low():
    v = gate.judge(answer(finding(severity="low")), {"app/a.py"}, cfg(fail_on="low"), TODAY)
    assert v.label == "BLOCK"


def test_file_not_changed_is_note():
    v = gate.judge(answer(finding()), {"other.py"}, cfg(), TODAY)
    assert v.code == 0 and len(v.notes) == 1 and not v.blocking


def test_suppression_by_glob():
    v = gate.judge(answer(finding()), {"app/a.py"}, cfg(suppressions=(sup("app/*.py"),)), TODAY)
    assert v.code == 0 and len(v.suppressed) == 1 and not v.notes


def test_suppression_glob_no_match():
    v = gate.judge(answer(finding()), {"app/a.py"}, cfg(suppressions=(sup("lib/*"),)), TODAY)
    assert v.code == 1


def test_suppression_cwe_match_and_mismatch():
    c1 = cfg(suppressions=(sup(cwe="CWE-22"),))
    c2 = cfg(suppressions=(sup(cwe="CWE-79"),))
    assert gate.judge(answer(finding()), {"app/a.py"}, c1, TODAY).code == 0
    assert gate.judge(answer(finding()), {"app/a.py"}, c2, TODAY).code == 1


def test_low_finding_matching_suppression_is_note_not_suppressed():
    v = gate.judge(answer(finding(severity="low")), {"app/a.py"},
                   cfg(suppressions=(sup(),)), TODAY)
    assert len(v.notes) == 1 and not v.suppressed


def test_expiry_boundary():
    s = sup(expires=TODAY)
    live = gate.judge(answer(finding()), {"app/a.py"}, cfg(suppressions=(s,)), TODAY)
    assert live.code == 0 and live.expired == []
    late = gate.judge(answer(finding()), {"app/a.py"}, cfg(suppressions=(s,)),
                      TODAY + timedelta(days=1))
    assert late.code == 1 and late.expired == [s] and not late.suppressed


# ---- load_config ----

def test_config_from_base(repo):
    base = commit(repo, {".ai-security-gate.toml": 'fail_on = "low"\n'})
    head = commit(repo, {".ai-security-gate.toml": 'fail_on = "critical"\n'})
    c, notice = gate.load_config(repo, base, head)
    assert c.fail_on == "low" and notice is None


def test_config_only_in_head_gives_notice(repo):
    base = commit(repo, {"x": "1"})
    head = commit(repo, {".ai-security-gate.toml": 'effort = "max"\n'})
    c, notice = gate.load_config(repo, base, head)
    assert c.effort == "max"
    assert notice == ("NOTICE: the base commit has no gate config; "
                      "suppressions in the change under review are ignored")


def test_head_only_config_drops_suppressions_and_loosened_limits(repo):
    text = ('fail_on = "critical"\nmin_confidence = "high"\ntriage_min_severity = "low"\n'
            'max_input_tokens = 800000\n[[suppress]]\npath = "a/*"\nreason = "why"\n'
            'expires = 2027-05-18\n')
    base = commit(repo, {"x": "1"})
    head = commit(repo, {".ai-security-gate.toml": text})
    c, notice = gate.load_config(repo, base, head)
    assert c.suppressions == ()
    assert (c.fail_on, c.min_confidence, c.triage_min_severity) == ("high", "medium", "low")
    assert c.max_input_tokens == 800000
    assert notice == gate.NOTICE_HEAD


def test_head_only_config_keeps_stricter_head_limits(repo):
    base = commit(repo, {"x": "1"})
    head = commit(repo, {".ai-security-gate.toml":
                         'fail_on = "low"\nmin_confidence = "low"\n'
                         'triage_min_severity = "critical"\n'})
    c, _ = gate.load_config(repo, base, head)
    assert (c.fail_on, c.min_confidence, c.triage_min_severity) == ("low", "low", "high")


def test_base_config_wins_over_head_without_notice(repo):
    base = commit(repo, {".ai-security-gate.toml": 'fail_on = "critical"\n'})
    head = commit(repo, {".ai-security-gate.toml": 'fail_on = "low"\n'})
    c, notice = gate.load_config(repo, base, head)
    assert c.fail_on == "critical" and notice is None


def test_config_in_neither_defaults(repo):
    base = commit(repo, {"x": "1"})
    head = commit(repo, {"x": "2"})
    c, notice = gate.load_config(repo, base, head)
    assert c == gate.Config() and notice is None and c.suppressions == ()
    assert (c.fail_on, c.min_confidence, c.effort) == ("high", "medium", "medium")


def test_config_full_with_suppression(repo):
    text = ('fail_on = "medium"\nmax_seconds = 5\n[[suppress]]\npath = "a/*"\n'
            'cwe = "CWE-22"\nreason = "why"\nexpires = 2027-05-18\n')
    base = commit(repo, {".ai-security-gate.toml": text})
    c, _ = gate.load_config(repo, base, base)
    assert c.max_seconds == 5
    assert c.suppressions == (gate.Suppression("a/*", "CWE-22", "why", date(2027, 5, 18)),)


def test_config_bad_base_is_error(repo):
    commit(repo, {"x": "1"})
    with pytest.raises(gate.ConfigError):
        gate.load_config(repo, "deadbeef", "HEAD")


@pytest.mark.parametrize("env", [("LC_ALL", "C"), ("LANG", "de_DE.UTF-8")])
def test_config_absent_at_base_is_locale_independent(repo, monkeypatch, env):
    monkeypatch.setenv(*env)
    base = commit(repo, {"x": "1"})
    head = commit(repo, {".ai-security-gate.toml": 'effort = "max"\n'})
    c, notice = gate.load_config(repo, base, head)
    assert c.effort == "max" and notice == gate.NOTICE_HEAD
    with pytest.raises(gate.ConfigError):
        gate.load_config(repo, "deadbeef", head)
    with pytest.raises(gate.ConfigError):
        gate.load_config(repo, base, "deadbeef")


SUP_OK = 'path = "a"\nreason = "r"\nexpires = 2027-01-01\n'
BAD_CONFIGS = {
    "unknown top key": 'bogus = 1\n',
    "unknown suppress key": f'[[suppress]]\n{SUP_OK}extra = 1\n',
    "wrong type str": 'fail_on = 3\n',
    "wrong type int": 'max_tokens = "5"\n',
    "bool as int": 'max_tokens = true\n',
    "zero int": 'max_requests = 0\n',
    "bad fail_on": 'fail_on = "severe"\n',
    "bad min_confidence": 'min_confidence = "none"\n',
    "bad effort": 'effort = "ultra"\n',
    "no reason": '[[suppress]]\npath = "a"\nexpires = 2027-01-01\n',
    "empty reason": '[[suppress]]\npath = "a"\nreason = ""\nexpires = 2027-01-01\n',
    "no path or id": '[[suppress]]\nreason = "r"\nexpires = 2027-01-01\n',
    "empty id": '[[suppress]]\nid = ""\nreason = "r"\nexpires = 2027-01-01\n',
    "id type": '[[suppress]]\nid = 5\nreason = "r"\nexpires = 2027-01-01\n',
    "cwe without path": '[[suppress]]\nid = "CVE-1"\ncwe = "CWE-22"\nreason = "r"\n'
                        'expires = 2027-01-01\n',
    "id suppression no reason": '[[suppress]]\nid = "CVE-1"\nexpires = 2027-01-01\n',
    "triage_min_severity type": 'triage_min_severity = 3\n',
    "bad triage_min_severity": 'triage_min_severity = "severe"\n',
    "empty path": '[[suppress]]\npath = ""\nreason = "r"\nexpires = 2027-01-01\n',
    "cwe lowercase": '[[suppress]]\ncwe = "cwe-22"\n' + SUP_OK,
    "cwe trailing space": '[[suppress]]\ncwe = "CWE-22 "\n' + SUP_OK,
    "cwe type": '[[suppress]]\ncwe = 22\n' + SUP_OK,
    "no expires": '[[suppress]]\npath = "a"\nreason = "r"\n',
    "expires not date": '[[suppress]]\npath = "a"\nreason = "r"\nexpires = "2027-01-01"\n',
    "expires datetime": '[[suppress]]\npath = "a"\nreason = "r"\nexpires = 2027-01-01T00:00:00\n',
    "bad toml": 'fail_on = \n',
}


@pytest.mark.parametrize("text", BAD_CONFIGS.values(), ids=BAD_CONFIGS.keys())
def test_config_errors(repo, text):
    base = commit(repo, {".ai-security-gate.toml": text})
    with pytest.raises(gate.ConfigError):
        gate.load_config(repo, base, base)


# ---- validate_answer ----

@pytest.fixture
def root(tmp_path):
    r = tmp_path / "head"
    (r / "app").mkdir(parents=True)
    (r / "app" / "a.py").write_text("one\ntwo\nthree\n")
    (r / "sub" / ".git").mkdir(parents=True)
    (r / "sub" / ".git" / "config").write_text("x\n")
    (r / ".git").mkdir()
    (r / ".git" / "config").write_text("x\n")
    (tmp_path / "outside.py").write_text("x\n")
    (r / "link.py").symlink_to(tmp_path / "outside.py")
    return r


def test_valid_answer_returns_dict(root):
    a = answer(finding(line=3))
    assert gate.validate_answer(a, root) == a
    import json
    assert gate.validate_answer(json.dumps(a), root) == a


def test_valid_zero_findings_passes(root):
    a = gate.validate_answer('{"summary": "ok", "findings": [], "triage": [], "scan": []}', root)
    assert gate.judge(a, set(), cfg(), TODAY).label == "PASS"


def bad(**kw):
    return answer(finding(**kw))


def without(key):
    f = finding()
    del f[key]
    return answer(f)


BAD_ANSWERS = {
    "not json": "{nope",
    "not object": "[1]",
    "no summary": {"findings": []},
    "summary type": {"summary": 1, "findings": []},
    "no findings": {"summary": "s", "triage": []},
    "no triage": {"summary": "s", "findings": [], "scan": []},
    "no scan": {"summary": "s", "findings": [], "triage": []},
    "scan type": {"summary": "s", "findings": [], "triage": [], "scan": {}},
    "triage type": {"summary": "s", "findings": [], "triage": {}, "scan": []},
    "findings type": {"summary": "s", "findings": {}, "triage": [], "scan": []},
    "finding not object": {"summary": "s", "findings": [1], "triage": [], "scan": []},
    "missing key": without("fix"),
    "extra key": bad(extra="x"),
    "title type": bad(title=1),
    "line type": bad(line="1"),
    "line bool": bad(line=True),
    "line float": bad(line=1.0),
    "bad severity": bad(severity="severe"),
    "bad confidence": bad(confidence="certain"),
    "bad cwe": bad(cwe="CWE-x"),
    "cwe lowercase": bad(cwe="cwe-22"),
    "cwe trailing newline": bad(cwe="CWE-22\n"),
    "empty file": bad(file=""),
    "line zero": bad(line=0),
    "line negative": bad(line=-2),
    "line past end": bad(line=4),
    "missing file": bad(file="app/none.py"),
    "directory": bad(file="app"),
    "absolute": bad(file="/etc/passwd"),
    "dotdot": bad(file="app/../app/a.py"),
    "dotdot escape": bad(file="../outside.py"),
    "in .git": bad(file=".git/config"),
    "nested .git": bad(file="sub/.git/config"),
    "symlink out": bad(file="link.py"),
}


@pytest.mark.parametrize("raw", BAD_ANSWERS.values(), ids=BAD_ANSWERS.keys())
def test_invalid_answers(root, raw):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(raw, root)


def test_errors_share_base():
    assert issubclass(gate.InvalidAnswer, gate.GateError)
    assert issubclass(gate.ConfigError, gate.GateError)


# ---- triage: validate_answer ----

def tri_answer(*entries):
    return {"summary": "s", "findings": [], "triage": list(entries), "scan": []}


def tri_without(key):
    t = tri()
    del t[key]
    return t


BAD_TRIAGE = {
    "missing key": tri_without("reason"),
    "extra key": tri(extra="x"),
    "id type": tri(id=1),
    "package type": tri(package=None),
    "reason type": tri(reason=1),
    "file type": tri(file=1),
    "line type": tri(line="1"),
    "line bool": tri(line=True),
    "bad verdict": tri(verdict="maybe"),
    "bad confidence": tri(confidence="certain"),
    "reachable line zero": tri(line=0),
    "reachable missing file": tri(file="app/none.py"),
    "reachable empty file": tri(file=""),
    "reachable line past end": tri(line=4),
    "not_reachable line bool": tri(verdict="not_reachable", line=False),
    "unknown file type": tri(verdict="unknown", file=None),
    "not an object": 1,
}


@pytest.mark.parametrize("entry", BAD_TRIAGE.values(), ids=BAD_TRIAGE.keys())
def test_invalid_triage_entry(root, entry):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(tri_answer(entry), root, [scan()])


def test_valid_triage_returns_answer(root):
    a = tri_answer(tri(line=3))
    assert gate.validate_answer(a, root, [scan()]) == a


def test_empty_triage_with_empty_input_is_valid(root):
    assert gate.validate_answer(answer(), root)["triage"] == []
    assert gate.validate_answer(answer(), root, [])["triage"] == []


@pytest.mark.parametrize("entries", [
    [],
    [tri(), tri()],
    [tri(id="CVE-9")],
    [tri(package="other")],
    [tri(), tri(id="CVE-9")],
], ids=["pair missing", "pair twice", "pair not in input", "wrong package", "extra pair"])
def test_triage_pairs_must_match_input(root, entries):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(tri_answer(*entries), root, [scan()])


def test_triage_same_id_two_packages(root):
    a = tri_answer(tri(), tri(package="pkg2"))
    assert gate.validate_answer(a, root, [scan(), scan(package="pkg2")]) == a
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(tri_answer(tri(), tri()), root, [scan(), scan(package="pkg2")])


def test_triage_entries_without_input_are_rejected(root):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(tri_answer(tri()), root)


@pytest.mark.parametrize("verdict", ["not_reachable", "unknown"])
def test_non_reachable_file_and_line_are_cleared(root, verdict):
    sent = tri(verdict=verdict, file="/etc/passwd", line=999)
    out = gate.validate_answer(tri_answer(sent), root, [scan()])
    entry = out["triage"][0]
    assert (entry["file"], entry["line"]) == ("", 0)
    assert entry["verdict"] == verdict and entry["reason"] == "r"
    assert sent["file"] == "/etc/passwd"  # input not mutated


# ---- triage and scan: judge ----

@pytest.mark.parametrize("verdict", ["reachable", "not_reachable", "unknown"])
@pytest.mark.parametrize("conf", ["low", "medium", "high"])
def test_triage_clears_only_not_reachable_at_high(verdict, conf):
    t = tri(verdict=verdict, confidence=conf)
    v = gate.judge(answer(triage=[t]), set(), cfg(), TODAY)
    cleared = verdict == "not_reachable" and conf == "high"
    assert (v.triage_cleared == [t]) == cleared
    assert (v.triage_blocking == [t]) == (not cleared)
    assert v.code == (0 if cleared else 1)


@pytest.mark.parametrize("verdict", ["true_positive", "false_positive", "unknown"])
@pytest.mark.parametrize("conf", ["low", "medium", "high"])
def test_scan_clears_only_false_positive_at_high(verdict, conf):
    e = sc(verdict=verdict, confidence=conf)
    v = gate.judge(answer(scan=[e]), set(), cfg(), TODAY)
    cleared = verdict == "false_positive" and conf == "high"
    assert (v.scan_cleared == [e]) == cleared
    assert (v.scan_blocking == [e]) == (not cleared)
    assert v.code == (0 if cleared else 1)


def test_min_confidence_does_not_affect_scanner_entries():
    for mc in gate.CONFIDENCES:
        c = cfg(min_confidence=mc)
        assert gate.judge(answer(scan=[sc(verdict="false_positive", confidence="medium")]),
                          set(), c, TODAY).code == 1
        assert gate.judge(answer(triage=[tri(verdict="not_reachable", confidence="high")]),
                          set(), c, TODAY).code == 0


def test_triage_reachable_blocks_when_file_not_changed():
    v = gate.judge(answer(triage=[tri(file="elsewhere.py")]), {"app/a.py"}, cfg(), TODAY)
    assert v.code == 1 and v.label == "BLOCK" and v.blocking == []
    assert v.triage_blocking == [tri(file="elsewhere.py")]


def test_suppressions_play_no_part_in_judge_for_scanner_entries():
    c = cfg(suppressions=(id_sup(), sup("app/*")))
    v = gate.judge(answer(triage=[tri()], scan=[sc()]), {"app/a.py"}, c, TODAY)
    assert v.code == 1 and len(v.triage_blocking) == 1 and len(v.scan_blocking) == 1


def test_id_suppression_does_not_touch_change_finding():
    v = gate.judge(answer(finding()), {"app/a.py"}, cfg(suppressions=(id_sup(),)), TODAY)
    assert v.code == 1 and not v.suppressed


def test_code_is_one_from_triage_alone():
    v = gate.judge(answer(finding(severity="low"), triage=[tri()]), {"app/a.py"}, cfg(), TODAY)
    assert v.blocking == [] and v.code == 1


def test_code_is_one_from_scan_alone():
    v = gate.judge(answer(scan=[sc()]), set(), cfg(), TODAY)
    assert v.code == 1 and v.blocking == [] and not v.triage_blocking


def test_expired_listed_in_verdict():
    s = id_sup(expires=TODAY)
    late = gate.judge(answer(), set(), cfg(suppressions=(s,)), TODAY + timedelta(days=1))
    assert late.expired == [s]


# ---- scan: validate_answer ----

def scan_answer(*entries):
    return {"summary": "s", "findings": [], "triage": [], "scan": list(entries)}


def sc_without(key):
    e = sc()
    del e[key]
    return e


BAD_SCAN = {
    "missing key field": sc_without("key"),
    "missing reason": sc_without("reason"),
    "extra field": sc(file="app/a.py"),
    "key type": sc(key=1),
    "reason type": sc(reason=1),
    "bad verdict": sc(verdict="reachable"),
    "bad confidence": sc(confidence="certain"),
    "not an object": 1,
}


@pytest.mark.parametrize("entry", BAD_SCAN.values(), ids=BAD_SCAN.keys())
def test_invalid_scan_entry(root, entry):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(scan_answer(entry), root, (), code_in("S1"))


def test_valid_scan_returns_answer(root):
    a = scan_answer(sc(), sc(key="S2", verdict="false_positive"))
    assert gate.validate_answer(a, root, (), code_in("S1", "S2")) == a


@pytest.mark.parametrize("entries", [
    [],
    [sc(), sc()],
    [sc(key="S9")],
    [sc(), sc(key="S2")],
    [sc(key="S2")],
], ids=["key missing", "key twice", "unknown key", "extra key", "wrong key"])
def test_scan_keys_must_match_input(root, entries):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(scan_answer(*entries), root, (), code_in("S1"))


def test_scan_entries_without_input_are_rejected(root):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(scan_answer(sc()), root)


def test_scan_key_missing_from_two(root):
    with pytest.raises(gate.InvalidAnswer):
        gate.validate_answer(scan_answer(sc()), root, (), code_in("S1", "S2"))


# ---- baseline ----

def dep(id="CVE-1", pkg="pkg", target="req.txt"):
    return {"VulnerabilityID": id, "PkgName": pkg, "Target": target}


def code(rule="r1", file="a.py", line=1, tool="t"):
    return {"tool": tool, "tool_version": "1", "rule_id": rule, "severity": "high",
            "file": file, "line": line, "message": "m"}


def asup(path=None, id=None, cwe=None, expires=date(2027, 1, 1)):
    return gate.Suppression(path, cwe, "r", expires, id)


def base(deps, codes, *sups):
    return gate.baseline(deps, codes, cfg(suppressions=tuple(sups)), TODAY)


def test_baseline_no_suppressions_keeps_all_and_keys_code():
    b = base([dep()], [code(line=1), code(line=2)])
    assert b.deps_open == [dep()] and b.accepted == [] and b.expired == []
    assert [c["key"] for c in b.code_open] == ["S1", "S2"]
    assert b.code_open[0]["rule_id"] == "r1" and b.code_open[1]["line"] == 2


def test_baseline_path_suppression_on_each_kind():
    s = asup(path="req/*")
    b = base([dep(target="req/a.txt"), dep(id="CVE-2")], [code(file="req/x.py"), code()], s)
    assert [v["VulnerabilityID"] for v in b.deps_open] == ["CVE-2"]
    assert [f["file"] for f in b.code_open] == ["a.py"]
    assert [(k, x) for k, x, _ in b.accepted] == [("dependency", dep(target="req/a.txt")),
                                                  ("code", code(file="req/x.py"))]
    assert all(m is s for _, _, m in b.accepted)


def test_baseline_id_suppression_on_each_kind():
    s = asup(id="CVE-1")
    b = base([dep(), dep(id="CVE-2")], [code(rule="CVE-1"), code(rule="other")], s)
    assert [v["VulnerabilityID"] for v in b.deps_open] == ["CVE-2"]
    assert [f["rule_id"] for f in b.code_open] == ["other"]
    assert [k for k, _, _ in b.accepted] == ["dependency", "code"]


def test_baseline_id_is_exact_not_glob():
    b = base([dep()], [code(rule="CVE-1")], asup(id="CVE-*"))
    assert len(b.deps_open) == 1 and len(b.code_open) == 1


def test_baseline_path_with_id_needs_both():
    s = asup(path="req.txt", id="CVE-1")
    b = base([dep(), dep(target="other.txt"), dep(id="CVE-2")], [], s)
    assert [(v["VulnerabilityID"], v["Target"]) for v in b.deps_open] == [
        ("CVE-1", "other.txt"), ("CVE-2", "req.txt")]
    assert len(b.accepted) == 1


def test_baseline_cwe_suppression_accepts_no_scanner_finding():
    s = asup(path="*", cwe="CWE-22")
    b = base([dep()], [code()], s)
    assert len(b.deps_open) == 1 and len(b.code_open) == 1 and b.accepted == []


def test_baseline_expired_accepts_nothing():
    s = asup(path="*", expires=TODAY - timedelta(days=1))
    b = base([dep()], [code()], s)
    assert len(b.deps_open) == 1 and len(b.code_open) == 1
    assert b.accepted == [] and b.expired == [s]


def test_baseline_suppression_live_on_expiry_day():
    s = asup(path="*", expires=TODAY)
    b = base([dep()], [], s)
    assert b.deps_open == [] and b.expired == []


def test_baseline_pair_accepted_under_one_target_open_under_another():
    s = asup(path="fixtures/*")
    b = base([dep(target="fixtures/r.txt"), dep(target="app/r.txt")], [], s)
    assert [v["Target"] for v in b.deps_open] == ["app/r.txt"]
    assert len(b.accepted) == 1


def test_baseline_dedups_open_deps_by_id_and_package_after_suppression():
    b = base([dep(target="a"), dep(target="b"), dep(pkg="other", target="a")], [])
    assert [(v["PkgName"], v["Target"]) for v in b.deps_open] == [("pkg", "a"), ("other", "a")]


def test_baseline_keys_only_on_open_code_findings():
    s = asup(path="skip/*")
    b = base([], [code(file="skip/a.py"), code(line=1), code(file="skip/b.py"), code(line=2)], s)
    assert [(f["key"], f["line"]) for f in b.code_open] == [("S1", 1), ("S2", 2)]
    assert all("key" not in f for _, f, _ in b.accepted)


def test_matches_false_without_path():
    assert gate.matches(id_sup(), finding()) is False


# ---- suppression and config parsing ----

def test_config_id_only_suppression(repo):
    text = '[[suppress]]\nid = "CVE-1"\nreason = "why"\nexpires = 2027-05-18\n'
    base = commit(repo, {".ai-security-gate.toml": text})
    c, _ = gate.load_config(repo, base, base)
    assert c.suppressions == (gate.Suppression(None, None, "why", date(2027, 5, 18), "CVE-1"),)


def test_config_path_and_id_suppression(repo):
    text = '[[suppress]]\npath = "a"\nid = "CVE-1"\nreason = "w"\nexpires = 2027-05-18\n'
    base = commit(repo, {".ai-security-gate.toml": text})
    c, _ = gate.load_config(repo, base, base)
    assert c.suppressions[0].path == "a" and c.suppressions[0].id == "CVE-1"


def test_triage_min_severity_default_set_wrong():
    assert gate.parse_config({}).triage_min_severity == "high"
    assert gate.parse_config({"triage_min_severity": "low"}).triage_min_severity == "low"
    with pytest.raises(gate.ConfigError):
        gate.parse_config({"triage_min_severity": "severe"})
