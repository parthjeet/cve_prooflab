FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Bind mounts leave no trace in the image: the build context and the uv binary
# stay out of the final layers.
RUN --mount=type=bind,target=/ctx \
    --mount=from=ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d,source=/uv,target=/bin/uv \
    uv pip install --system --no-cache --require-hashes -r /ctx/requirements-dev.txt

COPY scripts/ci/proof_pytest.py /opt/proof_pytest.py

USER 65534
