#!/usr/bin/env bash
# Pick the review model from the approval comment of this run.
# Usage: pick_model.sh APPROVALS_FILE
# Env: ENVIRONMENT, APPROVER, DEFAULT_MODEL, ALLOWED_MODELS (space-separated).
# Prints the model ID on stdout, or one ERROR line on stderr and exits 1.
# The comment is data: only jq reads it, and the shell never evaluates it.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: pick_model.sh APPROVALS_FILE" >&2
  exit 2
fi
approvals="$1"

for var in ENVIRONMENT APPROVER DEFAULT_MODEL ALLOWED_MODELS; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is not set." >&2
    exit 2
  fi
done

if ! jq -e 'type == "array"' "$approvals" > /dev/null 2>&1; then
  echo "ERROR: cannot read the approvals of this run." >&2
  exit 1
fi

# JSON array of the distinct trimmed non-empty comments; null when no approval counts.
values="$(
  jq -c --arg env "$ENVIRONMENT" --arg who "$APPROVER" '
    [.[] | select(type == "object" and .state == "approved" and .user.login? == $who
        and ((.environments? // []) | map(.name? == $env) | any))] as $kept
    | if ($kept | length) == 0 then null
      else [$kept[] | (.comment // "") | tostring | gsub("^\\s+|\\s+$"; "") | select(length > 0)] | unique
      end' "$approvals"
)"

if [ "$values" = "null" ]; then
  echo "ERROR: no approval of $ENVIRONMENT by $APPROVER is on record." >&2
  exit 1
fi

case "$(jq 'length' <<< "$values")" in
  0)
    printf '%s\n' "$DEFAULT_MODEL"
    ;;
  1)
    if jq -e --arg allowed "$ALLOWED_MODELS" \
      '.[0] as $c | ($allowed | split(" ")) | index($c) != null' <<< "$values" > /dev/null; then
      jq -r '.[0]' <<< "$values"
    else
      echo "ERROR: the approval comment is not an allowed model ID. Allowed: ${ALLOWED_MODELS// /, }. Leave the comment empty for $DEFAULT_MODEL." >&2
      exit 1
    fi
    ;;
  *)
    echo "ERROR: this run holds approvals that name different models. Start a new run to change the model." >&2
    exit 1
    ;;
esac
