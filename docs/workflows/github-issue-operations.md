# GitHub Issue Operations

Shared helpers for the bug, feature, and task workflows. All three workflows use native GitHub issue types (not labels) and native sub-issue relationships (not body-only references).

## Linking files in issue bodies

When an issue body references a file in this repo (an ADR, a workflow doc, a source file, a skill, etc.), use a clickable GitHub blob URL — not a plain text path. A reader should be able to follow the reference in one click without copying a path and searching for it.

**Format:**

```
[display text](https://github.com/camunda/camunda-security-library/blob/main/<path>)
```

**Examples:**

- `` [ADR-0002](https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0002-placement-of-the-security-gateway-framework.md) `` instead of `` `docs/adr/0002-placement-of-the-security-gateway-framework.md` ``
- `` [architecture.md](https://github.com/camunda/camunda-security-library/blob/main/.claude/docs/architecture.md) `` instead of `` `.claude/docs/architecture.md` ``

**When this applies:**
- Any narrative reference a reader should be able to follow (Location in Code, Additional Context, referenced ADRs, patterns to follow).

**When this does NOT apply:**
- Inline code fences showing file paths inside a shell command (e.g., `grep foo docs/adr/*.md`) — those are commands, not navigation.
- Sibling, child, or parent issues — use `#<number>` for those; GitHub auto-links issues.

## Setting the issue type

The repo has these native issue types configured: `Bug`, `Feature`, `Task`, `Epic`, `Tech-debt`, `CVE`.

`gh issue create` does not yet support setting a type directly, so each workflow creates the issue first, then sets the type via a GraphQL mutation. Do NOT apply redundant labels like `bug`, `enhancement`, or `task` — the native type replaces them.

### Lookup the type ID

```bash
gh api graphql -f query='
query {
  repository(owner: "camunda", name: "camunda-security-library") {
    issueTypes(first: 10) { nodes { id name } }
  }
}' --jq '.data.repository.issueTypes.nodes[] | select(.name=="Task") | .id'
```

Replace `Task` with `Bug` or `Feature` as needed. The returned ID looks like `IT_kwDOACVKPs4ABBrE`.

### Apply the type

Once the issue is created, get its GraphQL node ID and run the mutation:

```bash
NODE_ID=$(gh api repos/camunda/camunda-security-library/issues/<number> --jq .node_id)
gh api graphql -f query="
mutation {
  updateIssueIssueType(input: {issueId: \"$NODE_ID\", issueTypeId: \"<TYPE_ID>\"}) {
    issue { number }
  }
}"
```

## Adding the issue to GitHub Projects

Every issue created via the `/bug`, `/feature`, `/task`, or `/epic` workflows must be added to **both** org projects:

| Project | Number | What it is |
|---|---|---|
| CSL Delivery | `241` | The library's own delivery board. |
| Identity | `209` | The Identity team umbrella that aggregates all of the team's work. |

Project 241 may already pick up new issues via the project's built-in auto-add automation, but do not rely on that — add the issue explicitly to both so it never depends on a project-side setting. Re-adding an item that is already on a board is a no-op, so this is always safe to run.

```bash
gh project item-add 241 --owner camunda --url "$URL"   # CSL Delivery
gh project item-add 209 --owner camunda --url "$URL"   # Identity team
```

`$URL` is the full issue URL returned by `gh issue create`. The command is idempotent and accepts the issue URL directly — no project node ID lookup needed.

## Linking sub-issues (native relationships)

GitHub supports native parent-child relationships. Use these instead of just mentioning issue numbers in the body — the GitHub UI renders progress ("0 of N completed") and shows sub-issues as a proper hierarchy.

### Link a child to a parent

```bash
CHILD_ID=$(gh api repos/camunda/camunda-security-library/issues/<child-number> --jq .id)
gh api -X POST repos/camunda/camunda-security-library/issues/<parent-number>/sub_issues \
  -F sub_issue_id=$CHILD_ID
```

**Important:** use `-F` (raw field) rather than `-f` (string field). The sub-issues API expects an integer.

### Verify

```bash
gh api repos/camunda/camunda-security-library/issues/<parent-number>/sub_issues \
  --jq '.[] | {number, title}'
```

## Complete issue creation example

Creating a bug issue with type and no labels:

```bash
# 1. Create the issue
URL=$(gh issue create --title "..." --body "...")
NUM=$(basename "$URL")

# 2. Look up the Bug type ID
TYPE_ID=$(gh api graphql -f query='query { repository(owner: "camunda", name: "camunda-security-library") { issueTypes(first: 10) { nodes { id name } } } }' \
  --jq '.data.repository.issueTypes.nodes[] | select(.name=="Bug") | .id')

# 3. Set the type
NODE_ID=$(gh api repos/camunda/camunda-security-library/issues/$NUM --jq .node_id)
gh api graphql -f query="mutation { updateIssueIssueType(input: {issueId: \"$NODE_ID\", issueTypeId: \"$TYPE_ID\"}) { issue { number } } }"

# 4. Add it to both org projects
gh project item-add 241 --owner camunda --url "$URL"   # CSL Delivery
gh project item-add 209 --owner camunda --url "$URL"   # Identity team
```

Creating a task and linking it to a parent feature:

```bash
URL=$(gh issue create --title "..." --body "...")
NUM=$(basename "$URL")

# Set Task type (same pattern as above, looking up "Task")
# ...

# Link as a sub-issue of the parent feature (#9 in this example)
CHILD_ID=$(gh api repos/camunda/camunda-security-library/issues/$NUM --jq .id)
gh api -X POST repos/camunda/camunda-security-library/issues/9/sub_issues \
  -F sub_issue_id=$CHILD_ID
```
