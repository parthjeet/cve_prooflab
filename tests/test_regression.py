"""Regression tests for CVE-2023-29159 (Starlette StaticFiles path traversal).

Each test asserts the safe behavior:
- a public file under /static is served;
- a sibling folder whose name starts with "static" is not served;
- an unrelated folder is not served.

On the vulnerable image, test_sibling_folder_is_not_served is expected to fail.
Requests go only to the lab server named by LAB_BASE_URL
(http://127.0.0.1:<port>).
"""

import http.client
import os
import re

import pytest

_URL_RE = re.compile(r"^http://127\.0\.0\.1:(\d{1,5})$")


def _get(host, port, path):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@pytest.fixture(scope="session")
def target():
    value = os.environ.get("LAB_BASE_URL")
    match = _URL_RE.match(value) if value is not None else None
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise RuntimeError(
            f"LAB_BASE_URL is {value!r}; required form is "
            "http://127.0.0.1:<port> with port 1-65535, no trailing slash"
        )
    host, port = "127.0.0.1", int(match.group(1))
    _get(host, port, "/static/index.html")
    return host, port


def test_public_file_is_served(target, record_property):
    status, body = _get(*target, "/static/index.html")
    record_property("status", status)
    record_property("body", body.decode("utf-8", "replace"))
    assert status == 200
    assert body == b"PUBLIC"


def test_sibling_folder_is_not_served(target, record_property):
    status, body = _get(*target, "/static/../static_disallow/marker.txt")
    record_property("status", status)
    record_property("body", body.decode("utf-8", "replace"))
    assert status == 404


def test_unrelated_folder_is_not_served(target, record_property):
    status, body = _get(*target, "/static/../other/marker.txt")
    record_property("status", status)
    record_property("body", body.decode("utf-8", "replace"))
    assert status == 404
