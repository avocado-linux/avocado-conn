#!/usr/bin/env bash
# Configures branch protection rules for the main branch.
# Idempotent — safe to re-run if settings drift.
# Requires: gh CLI authenticated with repo admin permissions.
set -euo pipefail

REPO="avocado-linux/avocado-conn"
BRANCH="main"

echo "Configuring branch protection for ${REPO}@${BRANCH}..."

gh api "repos/${REPO}/branches/${BRANCH}/protection" \
  --method PUT \
  --input - <<'EOF'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "Run Tests / Test Suite (stable)"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "require_last_push_approval": true,
    "required_approving_review_count": 1
  },
  "required_conversation_resolution": true,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false
}
EOF

echo "Branch protection configured successfully."
echo ""
echo "Verify with:"
echo "  gh api repos/${REPO}/branches/${BRANCH}/protection | jq '{"
echo "    checks: [.required_status_checks.checks[].context],"
echo "    strict: .required_status_checks.strict,"
echo "    enforce_admins: .enforce_admins.enabled,"
echo "    reviews: .required_pull_request_reviews | {dismiss_stale_reviews,require_code_owner_reviews,require_last_push_approval,required_approving_review_count},"
echo "    conversation_resolution: .required_conversation_resolution.enabled"
echo "  }'"
