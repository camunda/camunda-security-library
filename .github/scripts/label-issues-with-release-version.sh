#!/usr/bin/env bash
# Applies a `version:<RELEASE_VERSION>` label to every issue closed by a PR
# merged into the range between PREV_TAG (exclusive) and RELEASE_TAG (inclusive).
#
# Required environment variables:
#   REPO             owner/repo (e.g. camunda/camunda-security-library)
#   RELEASE_TAG       tag of the release just created (e.g. 0.1.0)
#   RELEASE_VERSION   version string used in the label (e.g. 0.1.0)
#
# Optional:
#   PREV_TAG          previous release tag to scope the range from. If unset,
#                     it is resolved via `git describe --tags --abbrev=0 "${RELEASE_TAG}^"`.
#
# Requires: gh CLI (authenticated via GH_TOKEN), git, jq.
set -euo pipefail

: "${REPO:?REPO is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_VERSION:?RELEASE_VERSION is required}"

LABEL="version:${RELEASE_VERSION}"

echo "Ensuring label '${LABEL}' exists on ${REPO}..."
gh label create "${LABEL}" \
  --repo "${REPO}" \
  --color ededed \
  --description "Marks an issue as being completely or in parts released in ${RELEASE_VERSION}" \
  --force

if [[ -z "${PREV_TAG:-}" ]]; then
  PREV_TAG=$(git describe --tags --abbrev=0 "${RELEASE_TAG}^" 2>/dev/null || true)
fi

# Use the releases/generate-notes API to get the exact set of PRs in this
# release's tag range — the same range that --generate-notes uses for the
# changelog. This avoids date-based approximations that can miss or include
# wrong PRs.
echo "Fetching release notes body to extract PR numbers (${PREV_TAG:-<first release>} → ${RELEASE_TAG})..."
generate_notes_args=(-f tag_name="${RELEASE_TAG}")
if [[ -n "${PREV_TAG}" ]]; then
  generate_notes_args+=(-f previous_tag_name="${PREV_TAG}")
fi

notes_body=$(gh api "repos/${REPO}/releases/generate-notes" \
  "${generate_notes_args[@]}" \
  --jq '.body' || true)

# Extract PR numbers from the generated notes markdown (format: #123)
pr_numbers=$(echo "${notes_body}" | grep -oP '#\K[0-9]+' | sort -un || true)

if [[ -z "${pr_numbers}" ]]; then
  echo "No merged PRs found in range — nothing to label."
  exit 0
fi

declare -A labeled_issues

for pr_number in ${pr_numbers}; do
  echo "Resolving closing issue references for PR #${pr_number}..."
  closing_issues=$(gh api graphql \
    -f query='
      query($owner: String!, $repo: String!, $pr: Int!) {
        repository(owner: $owner, name: $repo) {
          pullRequest(number: $pr) {
            closingIssuesReferences(first: 100) {
              nodes {
                number
              }
            }
          }
        }
      }' \
    -F owner="${REPO%%/*}" \
    -F repo="${REPO##*/}" \
    -F pr="${pr_number}" \
    --jq '.data.repository.pullRequest.closingIssuesReferences.nodes[].number' || true)

  for issue_number in ${closing_issues}; do
    labeled_issues["${issue_number}"]=1
  done
done

if [[ ${#labeled_issues[@]} -eq 0 ]]; then
  echo "No closing issue references found among merged PRs — nothing to label."
  exit 0
fi

for issue_number in "${!labeled_issues[@]}"; do
  echo "Applying '${LABEL}' to issue #${issue_number}..."
  gh issue edit "${issue_number}" --repo "${REPO}" --add-label "${LABEL}"
done

echo "Done. Labeled ${#labeled_issues[@]} issue(s) with '${LABEL}'."
