#!/usr/bin/env bash
# Applies a `version:<RELEASE_VERSION>` label to every issue closed by a PR
# merged into the range between PREV_TAG (exclusive) and RELEASE_TAG (inclusive).
#
# Required environment variables:
#   REPO             owner/repo (e.g. camunda/camunda-security-library)
#   RELEASE_TAG       tag of the release just created (e.g. 0.1.0)
#   RELEASE_VERSION   version string used in the label (e.g. 0.1.0)
#   RELEASE_BRANCH    branch the release was cut from/targets (used to resolve
#                     the previous tag and to scope the merged-PR search)
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
: "${RELEASE_BRANCH:?RELEASE_BRANCH is required}"

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

if [[ -n "${PREV_TAG}" ]]; then
  echo "Scoping merged PR search to commits between ${PREV_TAG} and ${RELEASE_TAG}."
  since_date=$(git log -1 --format=%aI "${PREV_TAG}" 2>/dev/null || true)
else
  echo "No previous tag found — scoping merged PR search to all PRs merged into ${RELEASE_BRANCH} up to ${RELEASE_TAG}."
  since_date=""
fi

until_date=$(git log -1 --format=%aI "${RELEASE_TAG}" 2>/dev/null || true)

if [[ -n "${since_date}" && -n "${until_date}" ]]; then
  merged_range="${since_date}..${until_date}"
elif [[ -n "${until_date}" ]]; then
  merged_range="<=${until_date}"
else
  merged_range=""
fi

search_query="is:pr is:merged base:${RELEASE_BRANCH}"
if [[ -n "${merged_range}" ]]; then
  search_query+=" merged:${merged_range}"
fi

echo "Searching merged PRs: ${search_query}"
pr_numbers=$(gh pr list \
  --repo "${REPO}" \
  --search "${search_query}" \
  --state merged \
  --json number \
  --jq '.[].number' || true)

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
            closingIssuesReferences(first: 50) {
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
