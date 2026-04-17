# GitHub Issue Operations

Shared helpers for the bug, feature, and task workflows. All three workflows use native GitHub issue types (not labels) and native sub-issue relationships (not body-only references).

## Setting the issue type

The repo has these native issue types configured: `Bug`, `Feature`, `Task`, `Epic`, `Tech-debt`, `CVE`.

`gh issue create` does not yet support setting a type directly, so each workflow creates the issue first, then sets the type via a GraphQL mutation. Do NOT apply redundant labels like `bug`, `enhancement`, or `task` — the native type replaces them.

### Lookup the type ID

```bash
gh api graphql -f query='
query {
  repository(owner: "camunda", name: "camunda-security-gateway") {
    issueTypes(first: 10) { nodes { id name } }
  }
}' --jq '.data.repository.issueTypes.nodes[] | select(.name=="Task") | .id'
```

Replace `Task` with `Bug` or `Feature` as needed. The returned ID looks like `IT_kwDOACVKPs4ABBrE`.

### Apply the type

Once the issue is created, get its GraphQL node ID and run the mutation:

```bash
NODE_ID=$(gh api repos/camunda/camunda-security-gateway/issues/<number> --jq .node_id)
gh api graphql -f query="
mutation {
  updateIssueIssueType(input: {issueId: \"$NODE_ID\", issueTypeId: \"<TYPE_ID>\"}) {
    issue { number }
  }
}"
```

## Linking sub-issues (native relationships)

GitHub supports native parent-child relationships. Use these instead of just mentioning issue numbers in the body — the GitHub UI renders progress ("0 of N completed") and shows sub-issues as a proper hierarchy.

### Link a child to a parent

```bash
CHILD_ID=$(gh api repos/camunda/camunda-security-gateway/issues/<child-number> --jq .id)
gh api -X POST repos/camunda/camunda-security-gateway/issues/<parent-number>/sub_issues \
  -F sub_issue_id=$CHILD_ID
```

**Important:** use `-F` (raw field) rather than `-f` (string field). The sub-issues API expects an integer.

### Verify

```bash
gh api repos/camunda/camunda-security-gateway/issues/<parent-number>/sub_issues \
  --jq '.[] | {number, title}'
```

## Complete issue creation example

Creating a bug issue with type and no labels:

```bash
# 1. Create the issue
URL=$(gh issue create --title "..." --body "...")
NUM=$(basename "$URL")

# 2. Look up the Bug type ID
TYPE_ID=$(gh api graphql -f query='query { repository(owner: "camunda", name: "camunda-security-gateway") { issueTypes(first: 10) { nodes { id name } } } }' \
  --jq '.data.repository.issueTypes.nodes[] | select(.name=="Bug") | .id')

# 3. Set the type
NODE_ID=$(gh api repos/camunda/camunda-security-gateway/issues/$NUM --jq .node_id)
gh api graphql -f query="mutation { updateIssueIssueType(input: {issueId: \"$NODE_ID\", issueTypeId: \"$TYPE_ID\"}) { issue { number } } }"
```

Creating a task and linking it to a parent feature:

```bash
URL=$(gh issue create --title "..." --body "...")
NUM=$(basename "$URL")

# Set Task type (same pattern as above, looking up "Task")
# ...

# Link as a sub-issue of the parent feature (#9 in this example)
CHILD_ID=$(gh api repos/camunda/camunda-security-gateway/issues/$NUM --jq .id)
gh api -X POST repos/camunda/camunda-security-gateway/issues/9/sub_issues \
  -F sub_issue_id=$CHILD_ID
```
