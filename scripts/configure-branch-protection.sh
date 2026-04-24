#!/usr/bin/env bash
# Configures branch protection for the main branch via a single GitHub Ruleset.
# Idempotent — safe to re-run if settings drift.
# Requires: gh CLI authenticated with repo admin permissions.
set -euo pipefail

REPO="avocado-linux/avocado-conn"
BRANCH="main"
RULESET_NAME="main branch protection"

echo "Configuring branch protection for ${REPO}@${BRANCH}..."

# Remove classic branch protection if present
if gh api "repos/${REPO}/branches/${BRANCH}/protection" >/dev/null 2>&1; then
  echo "  Removing classic branch protection..."
  gh api "repos/${REPO}/branches/${BRANCH}/protection" --method DELETE >/dev/null
fi

# Fetch all rulesets once
RULESETS=$(gh api "repos/${REPO}/rulesets")

# Remove auto-created Copilot ruleset if it exists as a separate entry
COPILOT_ID=$(echo "$RULESETS" | jq -r '.[] | select(.name == "Copilot review for default branch") | .id // empty')
if [[ -n "$COPILOT_ID" ]]; then
  echo "  Removing auto-created Copilot ruleset (id: ${COPILOT_ID})..."
  gh api "repos/${REPO}/rulesets/${COPILOT_ID}" --method DELETE >/dev/null
fi

# Create or update our consolidated ruleset
EXISTING_ID=$(echo "$RULESETS" | jq -r --arg n "$RULESET_NAME" '.[] | select(.name == $n) | .id // empty')

if [[ -n "$EXISTING_ID" ]]; then
  echo "  Updating existing ruleset (id: ${EXISTING_ID})..."
  METHOD="PUT"
  ENDPOINT="repos/${REPO}/rulesets/${EXISTING_ID}"
else
  echo "  Creating new ruleset..."
  METHOD="POST"
  ENDPOINT="repos/${REPO}/rulesets"
fi

gh api "$ENDPOINT" --method "$METHOD" --input - <<'PAYLOAD'
{
  "name": "main branch protection",
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
echo "  gh api repos/${REPO}/rulesets | jq '.[] | select(.name == \"${RULESET_NAME}\") | {id,name,enforcement}'"
