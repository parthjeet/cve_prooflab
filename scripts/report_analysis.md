# Analysis of CVE-2023-29159 in the lab

This file is the hand-written input of `scripts/generate_report.py`. It keeps hypotheses apart from scanner findings and test results. Figures that a scan or a test produces are not typed here; the report reads them from `reports/` at run time.

## Observed facts

- The advisory [GHSA-v5gw-mw7f-84px](https://github.com/advisories/GHSA-v5gw-mw7f-84px) gives the affected range `>= 0.13.5, < 0.27.0` for `starlette` (pip), and `0.27.0` as the patched version. The NVD record for CVE-2023-29159 gives the same range (`versionStartIncluding 0.13.5`, `versionEndExcluding 0.27.0`), read on 2026-11-18 through the NVD API.
- The lab app is one route: `Mount("/static", app=StaticFiles(directory="static"), name="static")` in `app/app.py`. Next to `static/`, the working directory holds `static_disallow/` and `other/`, each with one marker file.
- In `starlette==0.26.1`, as installed in the vulnerable image, `StaticFiles.lookup_path` decides whether a requested path stays inside the served folder with this line (`starlette/staticfiles.py`, line 172):

  ```python
  if os.path.commonprefix([full_path, directory]) != directory:
  ```

  `os.path.commonprefix` compares strings one character at a time. It does not compare path components.
- For the lab's paths, Python 3.12 returns:

  | Resolved path | `commonprefix` with `/srv/app/static` | `commonpath` with `/srv/app/static` |
  |---|---|---|
  | `/srv/app/static/index.html` | `/srv/app/static` | `/srv/app/static` |
  | `/srv/app/static_disallow/marker.txt` | `/srv/app/static` | `/srv/app` |
  | `/srv/app/other/marker.txt` | `/srv/app/` | `/srv/app` |

  With `commonprefix`, the sibling folder passes the check, because its name starts with `static`. With `commonpath`, it fails.
- The fix is commit [`1797de4`](https://github.com/encode/starlette/commit/1797de464124b090f10cf570441e8292936d63e3). It changes that one line from `commonprefix` to `commonpath`, and adds a test that requests `/../static1.txt` and `/../static_disallow/index.html`.
- The advisory classes the flaw as CWE-22 (path traversal), with the CVSS v4 vector `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`: low confidentiality impact, no integrity or availability impact. The changed line guards a file lookup: it decides which file `StaticFiles` may read and return. The lab does not test any effect other than the read of one marker file.
- Changes between `0.26.1` and `0.27.0`, from the 0.27.0 release notes and from a diff of the two installed packages:

  | Change | Files in the installed package | Touches `StaticFiles` |
  |---|---|---|
  | Replace `commonprefix` by `commonpath` in `StaticFiles` (the fix) | `staticfiles.py`, one line | Yes |
  | Convert `ImportError` into `ModuleNotFoundError` (#2135) | `formparsers.py`, `requests.py`, `schemas.py`, `templating.py` | No |
  | Minify JSON websocket data in `send_json` (#2128) | `websockets.py`, `testclient.py` | No |
  | Correct a `RuntimeError` message in websockets (#2141) | `websockets.py` | No |
  | Version number | `__init__.py` | No |
  | Formatting only (blank lines, a trailing comma) | `_compat.py`, `endpoints.py`, `middleware/cors.py`, `schemas.py`, `templating.py` | No |

  The fix is the only change in `staticfiles.py`. The `ModuleNotFoundError` change sits in import guards for optional packages (`python-multipart`, `jinja2`, `pyyaml`) that neither image installs. The websocket changes are in `websockets.py` and `testclient.py`; the lab app has no websocket route.
- The two images differ only in the `starlette` pin. The compiled requirements files differ only in that pin and its hashes, and `pip list` in each image shows the same seven other packages at the same versions.
- On the host (Python 3.12.3, `uvicorn==0.54.0`, client `http.client`, which sends `..` unchanged), before the lab was built:
  - `GET /static/../static_disallow/marker.txt` returned 200 with the marker text on `0.26.1`, and 404 on `0.27.0`.
  - `GET /static/../other/marker.txt` returned 404 on both.
  - `GET /static/index.html` returned 200 on both.
- In the Trivy scans, the `starlette` findings of the two images differ only by CVE-2023-29159. The other `starlette` findings are the same in both images, so the patched pin still carries later advisories.

## Hypotheses

- **H1. The app reaches the affected code.** Every request under `/static` goes to `StaticFiles.lookup_path`, the function that holds the flawed check.
- **H2. Exposure needs a sibling whose name starts with the served folder's name.** On `0.26.1`, a request can read files in `static_disallow/`, because `/srv/app/static` is a string prefix of `/srv/app/static_disallow`. It cannot read files in `other/`.
- **H3. The server passes `..` to the app unchanged.** `uvicorn==0.54.0` does not normalize the request path, so `StaticFiles` sees the `..` and resolves it.
- **H4. The version change fixes the flaw.** Moving from `0.26.1` to `0.27.0` closes the sibling-folder read, and no other difference between the images causes the changed result.

## Checks

- **H1.** Observed: `app/app.py` mounts `StaticFiles` and nothing else, and the installed `0.26.1` source holds the `commonprefix` check in `lookup_path`. A 200 response for `/static/index.html` shows the request reached `StaticFiles`. Checked again in Phase 4 by `test_public_file_is_served` on both images.
- **H2.** Phase 4, in containers: `test_sibling_folder_is_not_served` fails on the vulnerable image (status 200 with the marker text) and passes on the patched image (404). `test_unrelated_folder_is_not_served` passes on both (404). If `other/` were readable, H2 would be wrong.
- **H3.** Phase 4: a 200 for the sibling request on the vulnerable image can only happen if `..` reached the app. The host run already showed this for `uvicorn==0.54.0`; Phase 4 repeats it inside the image.
- **H4.** The requirements files differ only in the `starlette` pin. The package diff above shows the fix is the only change in `staticfiles.py`. Inferred from that diff, not tested: no other change runs when the lab app serves a request. Phase 4 shows the sibling request changes from 200 to 404 between the two images, and the other two requests do not change.

## Remediation

- Upgrade `starlette` to `0.27.0` or later. The lab pins `0.27.0` because it is the first fixed version: it proves the fix with the smallest change between the two images.
- `0.27.0` is not the version to deploy. The patched scan still lists later `starlette` advisories, and the report counts them from `reports/trivy-patched.json`. A real service should move to the latest supported release.
- If an upgrade must wait, a stopgap follows from H2: keep no file or folder next to a served folder whose name starts with that folder's name. The lab tests this on one layout only (`other/` is not served on `0.26.1`). It is not a fix.
