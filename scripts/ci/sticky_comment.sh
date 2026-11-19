#!/usr/bin/env bash
# Post or update one sticky pull request comment.
# Usage: sticky_comment.sh BODY_FILE
# Env: GH_TOKEN, REPO, PR_NUMBER.
# The first line of BODY_FILE is the marker, for example <!-- name -->.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: sticky_comment.sh BODY_FILE" >&2
  exit 2
fi
body_file="$1"

if [[ ! "${PR_NUMBER:-}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: PR_NUMBER must be digits." >&2
  exit 2
fi
if [[ ! "${REPO:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "ERROR: REPO must look like OWNER/NAME." >&2
  exit 2
fi
if [ ! -f "$body_file" ]; then
  echo "ERROR: body file not found." >&2
  exit 2
fi

marker="$(head -n 1 "$body_file")"
if [[ ! "$marker" =~ ^\<!--\ [a-z0-9-]+\ --\>$ ]]; then
  echo "ERROR: the first line of the body file must be a marker like <!-- name -->." >&2
  exit 2
fi

id="$(
  gh api --paginate "repos/$REPO/issues/$PR_NUMBER/comments" \
    | jq -s --arg marker "$marker" \
      '[.[][] | select(.user.login == "github-actions[bot]" and (.body | startswith($marker)))] | first | .id // empty'
)"

if [ -n "$id" ]; then
  if [[ ! "$id" =~ ^[0-9]+$ ]]; then
    echo "ERROR: comment id is not digits." >&2
    exit 1
  fi
  gh api --method PATCH "repos/$REPO/issues/comments/$id" -F body=@"$body_file" > /dev/null
  echo "Updated comment $id."
else
  gh api --method POST "repos/$REPO/issues/$PR_NUMBER/comments" -F body=@"$body_file" > /dev/null
  echo "Created comment."
fi
