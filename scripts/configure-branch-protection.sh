#!/usr/bin/env bash
# Configures branch protection for the main branch via a single GitHub Ruleset.
# Idempotent — safe to re-run if settings drift.
# Requires: gh CLI (authenticated with repo admin permissions) and jq.
#
# Manual pre-steps (run once before the first time):
#   1. Remove classic branch protection (if present):
#      gh api -X DELETE repos/avocado-linux/avocado-conn/branches/main/protection
#   2. Remove the auto-created Copilot ruleset (if present):
#      gh api -X DELETE repos/avocado-linux/avocado-conn/rulesets/15509730
set -euo pipefail

REPO="avocado-linux/avocado-conn"
BRANCH="main"
RULESET_NAME="main branch protection"

if ! command -v gh >/dev/null 2>&1; then
  echo "Error: gh CLI is required but not installed or not in PATH." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required but not installed or not in PATH." >&2
  exit 1
fi

echo "Configuring branch protection for ${REPO}@${BRANCH}..."

RULESETS=$(gh api --paginate "repos/${REPO}/rulesets")
EXISTING_ID=$(echo "$RULESETS" | jq -r --arg n "$RULESET_NAME" '
  map(select(.name == $n)) |
  if length > 1 then error("multiple rulesets named \($n) found; resolve manually before re-running")
  elif length == 1 then .[0].id
  else empty
  end
')

if [[ -n "$EXISTING_ID" ]]; then
  echo "  Updating existing ruleset (id: ${EXISTING_ID})..."
  METHOD="PUT"
  ENDPOINT="repos/${REPO}/rulesets/${EXISTING_ID}"
else
  echo "  Creating new ruleset..."
  METHOD="POST"
  ENDPOINT="repos/${REPO}/rulesets"
fi

gh api "$ENDPOINT" --method "$METHOD" --input - <<PAYLOAD
{
  "name": "${RULESET_NAME}",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["~DEFAULT_BRANCH"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          {"context": "Run Tests / Test Suite (stable)"}
        ]
      }
    },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "copilot_code_review",
      "parameters": {
        "review_on_push": true,
        "review_draft_pull_requests": false
      }
    }
  ],
  "bypass_actors": []
}
PAYLOAD

echo "Branch protection ruleset configured successfully."
echo ""
echo "Verify with:"
echo "  gh api --paginate repos/${REPO}/rulesets | jq '.[] | select(.name == \"${RULESET_NAME}\") | {id,name,enforcement}'"
