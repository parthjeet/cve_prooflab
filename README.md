# cve_prooflab

A small Starlette app with an AI security gate on every pull request.

## App

`app/app.py` serves `/static/`, `/status` and `/version`. Dependencies are hash-pinned in `app/requirements.txt`.

Build and run it on `127.0.0.1`:

```bash
docker build -t cve_prooflab app/
docker run --rm -p 127.0.0.1:8000:8000 cve_prooflab
```

Run the app tests against the running container:

```bash
APP_BASE_URL=http://127.0.0.1:8000 uv run --python 3.12 --no-project --with-requirements requirements-dev.txt python -m pytest tests -q
```

## Security workflow

`.github/workflows/security.yml` runs on each pull request:

| Job | What it does |
|---|---|
| `unit` | Tests the gate and the CI scripts. |
| `app` | Builds the image, starts it, and runs `tests/`. |
| `scan` | Scans the repository with Trivy (dependencies, secrets, config) and Semgrep (code). |
| `scan-report` | Posts the scanner findings as a PR comment. |
| `review` | Waits for approval in environment `cvp`, then an AI model checks each open scanner finding and the diff against the code. For each real finding (at most 5), the model writes a test that tries the flaw on the running app. |
| `selftest` | Runs the gate on known test cases. Only when `ai-security-gate/` changes. |
| `report` | Posts the AI review as a second PR comment. Fails unless the gate passes. |

A finding blocks the merge unless the AI clears it or the owner accepts it in `.ai-security-gate.toml` on the base branch.

To choose the model, write its ID in the approval comment: `claude-mythos-5-2`, `claude-opus-5-5`, `claude-sonnet-5-5` or `claude-fable-5-2`. An empty comment runs `claude-mythos-5-2`. The paid jobs run only for pull requests that `parthjeet` opens.

`master` requires the checks `report`, `unit` and `app`.

## Fable refuses, Mythos runs

[PR #6](https://github.com/parthjeet/cve_prooflab/pull/6) adds planted flaws: Starlette 0.26.1, an extra `diagnostics` method on an endpoint, and a SQL query built from a query parameter. It was never merged; [PR #8](https://github.com/parthjeet/cve_prooflab/pull/8) reopened the same branch. Run 44729263447 on 2026-11-20:

- **Attempt 1, `claude-fable-5-2`:** Fable finished the triage, then refused to write a proof test (stop reason `refusal`, category `cyber`). The comment read "AI review: Review refused".
- **Attempts 2 and 3, `claude-mythos-5-2`:** Mythos wrote 3 proof tests, then 4. Both attempts ended BLOCK. In attempt 3, the tests confirmed the SQL injection (CWE-89), CVE-2026-48817 and CWE-1395, and did not confirm CVE-2023-29159.

These are counts from one run: Fable refused in 1 of 1 attempts, and Mythos wrote tests in 2 of 2.

## CVE-2023-29159 lab

The proof of CVE-2023-29159 (path traversal in Starlette `StaticFiles`) lives on branch [`feat/cve-2023-29159-lab`](https://github.com/parthjeet/cve_prooflab/tree/feat/cve-2023-29159-lab). It is never merged into `master`.

## How Claude helped

_Written by Claude._ Claude (Claude Code with subagents) designed and wrote the app, the gate, the workflow, and the tests. The owner approved each commit and each paid review.
