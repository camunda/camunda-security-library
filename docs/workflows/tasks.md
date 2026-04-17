# Creating Task Issues

This workflow creates GitHub task issues that are **small, self-contained, and independently mergeable**. A task can stand on its own, or it can be one of several tasks that together deliver a larger feature.

It applies when a user says "track this task", "create a task for X", "break this feature into tasks", or "we need to implement X".

Claude Code users: this workflow is also available as `/task`.

## What makes something a task (vs a feature)

- **Feature** — the outcome ("users should be able to bulk-assign roles"). Often too large to implement in a single PR.
- **Task** — a concrete unit of implementation work. Small enough to review in one sitting. Can be merged independently without breaking anything — either because it stands alone, or because it lands behind a boundary (no caller yet, feature flag, internal only) until the parent feature is complete.

A task issue can exist without a parent feature — use it for any standalone unit of work that's too small to be a feature but structured enough to warrant its own issue.

## Process

### 1. Confirm what you know

From the current session context, identify what you already know about:
- What concrete piece of work this task represents
- Whether this task has a parent feature issue (if so, which one)
- Why this task is independently mergeable — what boundary keeps it from breaking anything
- Where in the code the change lives
- What acceptance criteria define "done"

### 2. Fill gaps — ask only what you must

If any of these are missing and you cannot determine them from the current session, ask the user. Batch your questions into a single message.

**You MUST know before creating the issue:**
- What this task delivers (summary)
- Why it is safe to merge independently (the boundary — no caller yet, feature flag, internal only, additive change, etc.)

**You SHOULD know (investigate the codebase if needed):**
- Parent feature issue link (if applicable)
- Where to implement (file paths, modules, new files)
- What existing code to follow as a pattern
- What verification command confirms the task is done

**Do NOT ask the user for:**
- Information you can derive from the parent feature issue
- Implementation details you can determine from the architecture
- Patterns you can find in the codebase

### 3. Check size

Before creating the task, verify it is actually small:

- [ ] Scoped to a single concern (one port, one adapter, one service, one set of related tests)
- [ ] Reviewable in a single sitting (roughly under 400 lines of diff)
- [ ] Does not break the codebase at any point during or after merge
- [ ] Has a clear, verifiable completion point

If the task fails these checks, split it into smaller tasks.

### 4. Create the issue

Use `gh issue create` with the task template.

```
gh issue create \
  --label "task" \
  --title "<concise title>" \
  --body "<body>"
```

**Body structure:**

```markdown
## Summary
<One or two sentences — what this task delivers.>

## Parent Feature
<Link to parent feature issue, or "Standalone task — no parent feature.">

## Why This Is Independently Mergeable
<Explain the boundary: no caller yet / feature flag / internal only / additive change / etc. A reviewer should be able to see at a glance why merging this alone won't break anything.>

## Scope
**In scope:**
- <What this task includes>

**Out of scope:**
- <What this task explicitly does not include — defer to another task or the parent feature>

## Location in Code
<Specific file paths, modules, new files to create.>
<Existing classes to extend or follow as patterns — name them specifically.>

## Acceptance Criteria
- [ ] <Verifiable criterion — a behavior that works, a test that passes, a class that exists with a specific contract>
- [ ] <Each criterion must be checkable by an agent without human judgment>
- [ ] <Include a criterion that existing behavior is unchanged>

## Verification
<Exact command to run to confirm the task is complete, e.g., `mvn test -pl sgf-domain -Dtest=PolicyVersionRepositoryTest`>

## Additional Context
<Related ADRs, deployment strategy relevance, links to sibling tasks, design notes.>
```

### 5. Update the parent feature (if applicable)

If this task has a parent feature issue, add a checkbox to the parent's implementation plan linking to this task. For example, edit the parent feature issue body to add:

```markdown
## Implementation Plan
- [ ] #<task-1-number> — <short description>
- [ ] #<task-2-number> — <short description>
- [ ] #<this-task-number> — <short description>
```

### 6. Confirm with the user

Show the user the created issue URL and a one-line summary. If linked to a parent feature, mention that the parent has been updated. Ask if anything needs adjusting.

## Quality checks

Before creating, verify:
- [ ] The task is small enough to review in one sitting
- [ ] The "Why This Is Independently Mergeable" section gives a clear boundary
- [ ] Acceptance criteria are verifiable without human judgment
- [ ] The verification command is specific (not just "run all tests")
- [ ] If there's a parent feature, it is linked both ways (task references parent, parent's plan lists task)
