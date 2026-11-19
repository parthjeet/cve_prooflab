import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import gate  # noqa: E402
import scanner  # noqa: E402


def vuln(id="CVE-1", pkg="pkg", sev="HIGH", **kw):
    v = {"VulnerabilityID": id, "PkgName": pkg, "InstalledVersion": "1.0",
         "FixedVersion": "1.1", "Severity": sev, "Title": "t", "Description": "d"}
    v.update(kw)
    return v


def result(*vulns, cls="lang-pkgs"):
    return {"Target": "Python", "Class": cls, "Type": "python-pkg",
            "Vulnerabilities": list(vulns)}


def report(*results):
    return {"SchemaVersion": 2, "Results": list(results)}


def write(tmp_path, data):
    p = tmp_path / "r.json"
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return p


def load(tmp_path, data, level="high"):
    return scanner.load(write(tmp_path, data), level)


def test_error_base():
    assert issubclass(scanner.ScannerError, gate.GateError)
    assert scanner.MAX_TRIAGE == 25


def test_file_missing(tmp_path):
    with pytest.raises(scanner.ScannerError):
        scanner.load(tmp_path / "none.json", "high")


@pytest.mark.parametrize("data", [
    "{nope",
    "[]",
    {"Results": []},
    {"SchemaVersion": 1, "Results": []},
    {"SchemaVersion": "2", "Results": []},
    {"SchemaVersion": 2, "Results": "x"},
    {"SchemaVersion": 2, "Results": [1]},
    {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs", "Vulnerabilities": "x"}]},
    {"SchemaVersion": 2, "Results": [{"Class": "lang-pkgs", "Vulnerabilities": [1]}]},
    report(result({"PkgName": "p", "Severity": "HIGH"})),
    report(result(vuln(id=""))),
    report(result(vuln(id=5))),
    report(result({"VulnerabilityID": "CVE-1", "Severity": "HIGH"})),
    report(result(vuln(pkg=""))),
    report(result(vuln(Title=5))),
    report(result(vuln(Severity=5))),
    report(result(vuln(FixedVersion=None))),
], ids=lambda d: str(d)[:40])
def test_shape_errors(tmp_path, data):
    with pytest.raises(scanner.ScannerError):
        load(tmp_path, data)


def test_shape_error_in_dropped_result_still_raises(tmp_path):
    with pytest.raises(scanner.ScannerError):
        load(tmp_path, report(result({"PkgName": "p"}, cls="os-pkgs")))


def test_no_results_gives_empty(tmp_path):
    assert load(tmp_path, {"SchemaVersion": 2}) == []
    assert load(tmp_path, {"SchemaVersion": 2, "Results": None}) == []
    assert load(tmp_path, report()) == []


def test_null_or_absent_vulnerabilities_ok(tmp_path):
    data = report({"Class": "lang-pkgs"}, {"Class": "lang-pkgs", "Vulnerabilities": None})
    assert load(tmp_path, data) == []


def test_os_pkgs_dropped(tmp_path):
    data = report(result(vuln("CVE-1"), cls="os-pkgs"), result(vuln("CVE-2")))
    assert [f["VulnerabilityID"] for f in load(tmp_path, data)] == ["CVE-2"]


def test_result_without_class_dropped(tmp_path):
    r = result(vuln())
    del r["Class"]
    assert load(tmp_path, report(r)) == []


@pytest.mark.parametrize("level,kept", [
    ("low", ["L", "M", "H", "C"]),
    ("medium", ["M", "H", "C"]),
    ("high", ["H", "C"]),
    ("critical", ["C"]),
])
def test_severity_threshold_uppercase_input(tmp_path, level, kept):
    data = report(result(vuln("L", sev="LOW"), vuln("M", sev="MEDIUM"),
                         vuln("H", sev="HIGH"), vuln("C", sev="CRITICAL")))
    assert [f["VulnerabilityID"] for f in load(tmp_path, data, level)] == kept


def test_severity_case_insensitive(tmp_path):
    data = report(result(vuln("A", sev="High"), vuln("B", sev="critical")))
    assert [f["VulnerabilityID"] for f in load(tmp_path, data)] == ["A", "B"]


def test_unknown_and_odd_and_missing_severity_dropped(tmp_path):
    no_sev = vuln("D")
    del no_sev["Severity"]
    data = report(result(vuln("A", sev="UNKNOWN"), vuln("B", sev="SEVERE"),
                         vuln("C", sev=""), no_sev))
    assert load(tmp_path, data, "low") == []


def test_eight_keys_and_trivy_values(tmp_path):
    extra = vuln(Status="fixed", PkgPath="x", Layer={"Digest": "d"})
    f = load(tmp_path, report(result(extra)))[0]
    assert list(f) == ["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion",
                       "Severity", "Title", "Description", "Target"]
    assert f == {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "InstalledVersion": "1.0",
                 "FixedVersion": "1.1", "Severity": "HIGH", "Title": "t", "Description": "d",
                 "Target": "Python"}


def test_missing_optional_fields_become_empty(tmp_path):
    v = {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "Severity": "HIGH"}
    f = load(tmp_path, report(result(v)))[0]
    assert (f["InstalledVersion"], f["FixedVersion"], f["Title"], f["Description"]) == ("",) * 4
    assert f["Severity"] == "HIGH"


def test_dedup_keeps_first_by_id_and_package(tmp_path):
    data = report(result(vuln(Title="first"), vuln(Title="second"),
                         vuln(pkg="other", Title="third")),
                  result(vuln(Title="fourth")))
    assert [f["Title"] for f in load(tmp_path, data)] == ["first", "third"]


def test_report_order_kept(tmp_path):
    data = report(result(vuln("CVE-3"), vuln("CVE-1")), result(vuln("CVE-2")))
    assert [f["VulnerabilityID"] for f in load(tmp_path, data)] == ["CVE-3", "CVE-1", "CVE-2"]


def test_target_kept_and_empty_when_absent(tmp_path):
    r = result(vuln())
    del r["Target"]
    assert load(tmp_path, report(r))[0]["Target"] == ""
    assert load(tmp_path, report(result(vuln())))[0]["Target"] == "Python"


def test_target_must_be_string(tmp_path):
    r = result(vuln())
    r["Target"] = 5
    with pytest.raises(scanner.ScannerError):
        load(tmp_path, report(r))


def test_same_pair_under_two_targets_gives_two(tmp_path):
    a, b = result(vuln()), result(vuln())
    b["Target"] = "other.txt"
    out = load(tmp_path, report(a, b))
    assert [f["Target"] for f in out] == ["Python", "other.txt"]


def test_load_has_no_limit(tmp_path):
    assert len(load(tmp_path, report(result(*[vuln(f"CVE-{i}") for i in range(30)])))) == 30


def test_check_limits():
    scanner.check_limits([0] * 25, [0] * 25)
    with pytest.raises(scanner.ScannerError, match="limit reached: triage findings"):
        scanner.check_limits([0] * 26, [])
    with pytest.raises(scanner.ScannerError, match="limit reached: code scanner findings"):
        scanner.check_limits([], [0] * 26)
    assert scanner.MAX_SCAN == 25


def test_dedup_counts_after_filter(tmp_path):
    vulns = [vuln(f"CVE-{i}") for i in range(25)] * 2
    vulns += [vuln(f"CVE-L{i}", sev="LOW") for i in range(10)]
    assert len(load(tmp_path, report(result(*vulns)))) == 25


def test_real_report_shape(tmp_path):
    """Shape copied from a real Trivy 2 report: extra fields, an os-pkgs result, UNKNOWN."""
    lang = {"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg",
            "Packages": [{"Name": "pip", "Version": "25.0.1"}],
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2025-8869", "VendorIDs": ["GHSA-4xh5-x5gv-qwph"],
                "PkgName": "pip", "PkgPath": "usr/local/lib/python3.12/site-packages/x",
                "PkgIdentifier": {"PURL": "pkg:pypi/pip@25.0.1", "UID": "7d864d9a4bf3bfe8"},
                "InstalledVersion": "25.0.1", "FixedVersion": "25.3", "Status": "fixed",
                "Layer": {"Digest": "sha256:a", "DiffID": "sha256:b"},
                "SeveritySource": "ghsa", "PrimaryURL": "https://example.test/x",
                "DataSource": {"ID": "ghsa", "Name": "n", "URL": "u"},
                "Fingerprint": "sha256:c", "Title": "pip: missing checks",
                "Description": "line one\nline two", "Severity": "MEDIUM",
                "CweIDs": ["CWE-59"], "CVSS": {"ghsa": {"V3Score": 5.3}},
                "References": ["https://example.test/r"],
                "PublishedDate": "2025-09-24T15:15:00Z"}, {
                "VulnerabilityID": "CVE-2025-9999", "PkgName": "anyio",
                "InstalledVersion": "4.0.0", "FixedVersion": "4.1.0", "Status": "fixed",
                "Title": "anyio issue", "Severity": "HIGH"}]}
    os_res = {"Target": "debian", "Class": "os-pkgs", "Type": "debian",
              "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-1", "PkgName": "libc6",
                                   "InstalledVersion": "2.36", "Severity": "UNKNOWN"}]}
    data = {"SchemaVersion": 2, "ArtifactName": "img:tag", "ArtifactType": "container_image",
            "Metadata": {"OS": {"Family": "debian"}}, "Results": [os_res, lang]}
    out = load(tmp_path, data, "medium")
    assert [(f["VulnerabilityID"], f["PkgName"]) for f in out] == [
        ("CVE-2025-8869", "pip"), ("CVE-2025-9999", "anyio")]
    assert out[1]["Description"] == "" and out[0]["Description"] == "line one\nline two"
    assert [f["VulnerabilityID"] for f in load(tmp_path, data, "high")] == ["CVE-2025-9999"]


# ---- SARIF ----

def res(rule="r1", line=3, uri="a/b.py", **kw):
    r = {"ruleId": rule, "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                             "region": {"startLine": line}}}]}
    r.update(kw)
    return r


def run(*results, rules=None, name="tool-x", **driver):
    d = {"name": name, **driver}
    if rules is not None:
        d["rules"] = rules
    return {"tool": {"driver": d}, "results": list(results)}


def sarif(*runs):
    return {"version": "2.1.0", "runs": list(runs)}


def sload(tmp_path, data, level="low"):
    return scanner.load_sarif(write(tmp_path, data), level)


def sev_of(tmp_path, result_kw=None, rule=None):
    r = res(**(result_kw or {}))
    rules = [{"id": "r1", **rule}] if rule is not None else None
    findings, _ = sload(tmp_path, sarif(run(r, rules=rules)))
    return findings[0]["severity"] if findings else None


@pytest.mark.parametrize("data", [
    "{nope",
    "[]",
    {"runs": []},
    {"version": "2.0.0", "runs": []},
    {"version": "2.1.0"},
    {"version": "2.1.0", "runs": "x"},
    {"version": "2.1.0", "runs": [1]},
    sarif({"results": []}),
    sarif({"tool": {"driver": {}}}),
    sarif({"tool": {"driver": {"name": ""}}}),
    sarif({"tool": {"driver": {"name": 5}}}),
    sarif({"tool": {"driver": {"name": "t"}}, "results": "x"}),
    sarif({"tool": {"driver": {"name": "t"}}, "results": [1]}),
    sarif(run({"message": {"text": "m"}})),
    sarif(run(res(rule=""))),
    sarif(run(res(rule=5))),
    sarif(run(res(uri="/etc/passwd"))),
    sarif(run(res(uri="file:///etc/passwd"))),
    sarif(run(res(uri="../x.py"))),
    sarif(run(res(uri="a/../x.py"))),
    sarif(run(res(uri="%2e%2e/x.py"))),
], ids=lambda d: str(d)[:40])
def test_sarif_shape_errors(tmp_path, data):
    with pytest.raises(scanner.ScannerError):
        sload(tmp_path, data)


def test_sarif_file_missing(tmp_path):
    with pytest.raises(scanner.ScannerError):
        scanner.load_sarif(tmp_path / "none.sarif", "low")


def test_sarif_null_or_absent_results_ok(tmp_path):
    data = sarif({"tool": {"driver": {"name": "t"}}},
                 {"tool": {"driver": {"name": "u"}}, "results": None})
    findings, tools = sload(tmp_path, data)
    assert findings == [] and [t["name"] for t in tools] == ["t", "u"]


def test_sarif_finding_keys_and_values(tmp_path):
    data = sarif(run(res(), version="1.2", rules=[{"id": "r1", "defaultConfiguration":
                                                  {"level": "error"}}]))
    findings, tools = sload(tmp_path, data)
    assert findings == [{"tool": "tool-x", "tool_version": "1.2", "rule_id": "r1",
                         "severity": "high", "file": "a/b.py", "line": 3, "message": "m"}]
    assert list(findings[0]) == ["tool", "tool_version", "rule_id", "severity", "file",
                                 "line", "message"]
    assert tools == [{"name": "tool-x", "version": "1.2"}]


def test_sarif_version_fallbacks(tmp_path):
    _, t1 = sload(tmp_path, sarif(run(semanticVersion="2.0")))
    _, t2 = sload(tmp_path, sarif(run(version="1", semanticVersion="2.0")))
    _, t3 = sload(tmp_path, sarif(run()))
    assert (t1[0]["version"], t2[0]["version"], t3[0]["version"]) == ("2.0", "1", "")


@pytest.mark.parametrize("score,sev", [
    (9.0, "critical"), ("9.8", "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"),
])
def test_sarif_security_severity(tmp_path, score, sev):
    rule = {"properties": {"security-severity": score}}
    assert sev_of(tmp_path, {"level": "note"}, rule) == sev


def test_sarif_non_number_security_severity_falls_back_to_level(tmp_path):
    rule = {"properties": {"security-severity": "high"}}
    assert sev_of(tmp_path, {"level": "error"}, rule) == "high"


@pytest.mark.parametrize("level,sev", [("error", "high"), ("warning", "medium"),
                                       ("note", "low"), ("none", None)])
def test_sarif_level(tmp_path, level, sev):
    assert sev_of(tmp_path, {"level": level}) == sev


def test_sarif_level_default_is_warning(tmp_path):
    assert sev_of(tmp_path) == "medium"


def test_sarif_level_from_rule_default_configuration(tmp_path):
    assert sev_of(tmp_path, None, {"defaultConfiguration": {"level": "error"}}) == "high"


def test_sarif_result_level_beats_rule_level(tmp_path):
    assert sev_of(tmp_path, {"level": "note"},
                  {"defaultConfiguration": {"level": "error"}}) == "low"


def test_sarif_rule_found_by_rule_index(tmp_path):
    rules = [{"id": "other"}, {"id": "zzz", "properties": {"security-severity": "9.5"}}]
    findings, _ = sload(tmp_path, sarif(run(res(rule="r1", ruleIndex=1), rules=rules)))
    assert findings[0]["severity"] == "critical"


def test_sarif_kind_pass_skipped_fail_kept(tmp_path):
    data = sarif(run(res(rule="a", kind="pass"), res(rule="b", kind="fail"),
                     res(rule="c", kind="informational"), res(rule="d")))
    assert [f["rule_id"] for f in sload(tmp_path, data)[0]] == ["b", "d"]


def test_sarif_suppressions_ignored(tmp_path):
    r = res(suppressions=[{"kind": "inSource"}])
    assert len(sload(tmp_path, sarif(run(r)))[0]) == 1


def test_sarif_uri_decoded_and_dot_slash_stripped(tmp_path):
    f = sload(tmp_path, sarif(run(res(uri="./dir%20x/a.py"))))[0][0]
    assert f["file"] == "dir x/a.py"


def test_sarif_no_location(tmp_path):
    r = res()
    del r["locations"]
    r2 = res(rule="r2", locations=[])
    f = sload(tmp_path, sarif(run(r, r2)))[0]
    assert [(x["file"], x["line"]) for x in f] == [("", 0), ("", 0)]


@pytest.mark.parametrize("start,line", [(5, 5), (0, 0), (-1, 0), ("5", 0), (True, 0), (None, 0)])
def test_sarif_line(tmp_path, start, line):
    assert sload(tmp_path, sarif(run(res(line=start))))[0][0]["line"] == line


def test_sarif_message_cut_and_absent(tmp_path):
    long = res(rule="a", message={"text": "x" * 1500})
    none = res(rule="b")
    del none["message"]
    f = sload(tmp_path, sarif(run(long, none)))[0]
    assert len(f[0]["message"]) == 1000 and f[1]["message"] == ""


def test_sarif_dedup_keeps_first(tmp_path):
    a = res(message={"text": "first"})
    b = res(message={"text": "second"})
    c = res(line=4)
    f = sload(tmp_path, sarif(run(a, b, c)))[0]
    assert [(x["message"], x["line"]) for x in f] == [("first", 3), ("m", 4)]


def test_sarif_two_runs_two_tools(tmp_path):
    data = sarif(run(res(), name="one", version="1"), run(res(), name="two"))
    findings, tools = sload(tmp_path, data)
    assert tools == [{"name": "one", "version": "1"}, {"name": "two", "version": ""}]
    assert [f["tool"] for f in findings] == ["one", "two"]


def test_sarif_threshold_filter(tmp_path):
    data = sarif(run(res(rule="n", level="note"), res(rule="w", level="warning"),
                     res(rule="e", level="error")))
    assert [f["rule_id"] for f in sload(tmp_path, data, "medium")[0]] == ["w", "e"]
    assert [f["rule_id"] for f in sload(tmp_path, data, "high")[0]] == ["e"]
    assert sload(tmp_path, data, "critical")[0] == []
