# cve_prooflab

A small local lab that builds a vulnerable and a patched image of a Starlette app, scans both with Trivy, and checks one known flaw, CVE-2023-29159, with a safe test on `127.0.0.1`.

The full README (setup, safety scope, commands, results) comes with the report.

## Method

1. Scan both images with Trivy, and check that CVE-2023-29159 is reported for the vulnerable image only.
2. Read the advisory, the NVD record, and the fix, and write down what is observed and what is only a hypothesis (`scripts/report_analysis.md`).
3. Validate the flaw with a test that sends harmless GET requests to each container on `127.0.0.1`.
4. Patch by moving `starlette` from `0.26.1` to `0.27.0`, the first fixed version, and rerun the scan and the test.

### Tools

- Trivy 0.76.2, installed from the official GitHub release. Before the install, Aqua Security's advisory [GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) (a March 2026 supply chain attack on some Trivy releases) was read; 0.76.2 is not affected. The tarball's checksum matched `trivy_0.76.2_checksums.txt`, and `gh release verify-asset` confirmed it belongs to the release.
- uv 0.13.9, installed and checked the same way. Earlier uv versions carry advisories GHSA-hq85-5cpj-mr62, GHSA-4gg8-gxpx-9rph, and GHSA-pjjw-68hj-v9mw.
- Docker 29.10.0. Base image `python:3.12-slim`, pinned by digest.

### What the results prove, and what they do not

The validation runs each image in a container published on `127.0.0.1` only and sends three GET requests:

| Test | Request | Vulnerable `0.26.1` | Patched `0.27.0` |
|---|---|---|---|
| `test_public_file_is_served` | `/static/index.html` | pass | pass |
| `test_sibling_folder_is_not_served` | `/static/../static_disallow/marker.txt` | fail: 200 and the marker text | pass: 404 |
| `test_unrelated_folder_is_not_served` | `/static/../other/marker.txt` | pass | pass |

The results prove:

- In these images, `starlette==0.26.1` serves a file from a sibling folder whose name starts with `static`, and `starlette==0.27.0` does not.
- Neither version serves a file from an unrelated folder, so the flaw needs that sibling-name precondition.

Two earlier checks, not this test, tie the changed result to the fix: the two requirements files differ only in the `starlette` pin, and in the installed package the fix is the only change in `staticfiles.py` (`scripts/report_analysis.md`).

The results do not prove:

- That `0.27.0` is safe to deploy. The patched scan still lists later `starlette` advisories; use the latest supported release.
- Anything about other request patterns or folder layouts.
- Anything about a sibling file such as `static1.txt`. The advisory's proof of concept and the fix commit's test name that case; the lab tests a sibling folder only.
- Any effect of the flaw other than the read of one file.

### The flaw, in my words

_To be written by the repository owner after reading the fix commit [`1797de4`](https://github.com/encode/starlette/commit/1797de464124b090f10cf570441e8292936d63e3)._
