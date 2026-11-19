# cve_prooflab

A small Starlette app with an AI security gate on every pull request.

## App

`app/app.py` serves `/static/` and `/status`. Dependencies are hash-pinned in `app/requirements.txt`.

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
| `review` | Waits for approval in environment `cvp`, then an AI model checks each open scanner finding and the diff against the code. |
| `selftest` | Runs the gate on known test cases. Only when `ai-security-gate/` changes. |
| `report` | Posts the AI review as a second PR comment. Fails unless the gate passes. |

A scanner finding of medium severity or higher blocks the merge unless the AI clears it with high confidence or the owner accepts it in `.ai-security-gate.toml`. The gate reads that policy file from the base branch, so a pull request cannot change the rules that judge it.

To choose the model, write its ID in the approval comment: `claude-mythos-5-2`, `claude-opus-5-5`, `claude-sonnet-5-5` or `claude-fable-5-2`. An empty comment runs `claude-mythos-5-2`. The paid jobs run only for pull requests that `parthjeet` opens.

`master` requires the checks `report`, `unit` and `app`.

## CVE-2023-29159 lab

The proof of CVE-2023-29159 (path traversal in Starlette `StaticFiles`) lives on branch [`feat/cve-2023-29159-lab`](https://github.com/parthjeet/cve_prooflab/tree/feat/cve-2023-29159-lab). It is never merged into `master`.

## How Claude helped

_Written by Claude._ Claude (Claude Code with subagents) designed and wrote the app, the gate, the workflow, and the tests. The owner approved each commit and each paid review.
