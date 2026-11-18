FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Path of the hash-pinned requirements file in the build context. No default.
ARG REQUIREMENTS

# Bind mounts leave no trace in the image: the build context and the uv binary
# stay out of the final layers. The test is needed because an empty
# REQUIREMENTS does not fail on its own.
RUN --mount=type=bind,target=/ctx \
    --mount=from=ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d,source=/uv,target=/bin/uv \
    test -n "$REQUIREMENTS" && test -f "/ctx/$REQUIREMENTS" \
      || { echo "ERROR: build arg REQUIREMENTS='$REQUIREMENTS' is empty or names a file missing from the build context" >&2; exit 1; }; \
    uv pip install --system --no-cache --require-hashes -r "/ctx/$REQUIREMENTS"

RUN useradd --system --no-create-home app

WORKDIR /srv/app
COPY app.py ./
COPY static/ ./static/
COPY static_disallow/ ./static_disallow/
COPY other/ ./other/

USER app
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
