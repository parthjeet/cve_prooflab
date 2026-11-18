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


def test_seven_keys_and_trivy_values(tmp_path):
    extra = vuln(Status="fixed", PkgPath="x", Layer={"Digest": "d"})
    f = load(tmp_path, report(result(extra)))[0]
    assert list(f) == ["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion",
                       "Severity", "Title", "Description"]
    assert f == {"VulnerabilityID": "CVE-1", "PkgName": "pkg", "InstalledVersion": "1.0",
                 "FixedVersion": "1.1", "Severity": "HIGH", "Title": "t", "Description": "d"}


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


def test_limit_25_passes_26_raises(tmp_path):
    ok = report(result(*[vuln(f"CVE-{i}") for i in range(25)]))
    assert len(load(tmp_path, ok)) == 25
    over = report(result(*[vuln(f"CVE-{i}") for i in range(26)]))
    with pytest.raises(scanner.ScannerError, match="limit reached: triage findings"):
        load(tmp_path, over)


def test_limit_counts_after_filter_and_dedup(tmp_path):
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
