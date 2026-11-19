"""Tests for the running app.

Requests go only to the server named by APP_BASE_URL
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
        # putrequest sends the path as given, with no normalization.
        conn.putrequest("GET", path, skip_host=False)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@pytest.fixture(scope="session")
def target():
    value = os.environ.get("APP_BASE_URL")
    match = _URL_RE.match(value) if value is not None else None
    if not match or not 1 <= int(match.group(1)) <= 65535:
        raise RuntimeError(
            f"APP_BASE_URL is {value!r}; required form is "
            "http://127.0.0.1:<port> with port 1-65535, no trailing slash"
        )
    host, port = "127.0.0.1", int(match.group(1))
    _get(host, port, "/static/index.html")
    return host, port


def test_static_file_is_served(target):
    status, body = _get(*target, "/static/index.html")
    assert status == 200
    assert b"PUBLIC" in body


def test_path_escape_is_not_served(target):
    status, _ = _get(*target, "/static/../app.py")
    assert status == 404


def test_status_is_ok(target):
    status, body = _get(*target, "/status")
    assert status == 200
    assert body == b"OK"
