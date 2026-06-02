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
gh issue create --title "<concise title>" --body "<body>"
```

After creation:

1. Set the native issue type to `Task` — see [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md) for the command.
2. If this task has a parent feature, link it as a native sub-issue — also covered in [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md). Do NOT rely solely on body text for the parent link; use the sub-issues API so the GitHub UI renders the hierarchy and progress.
3. Add it to both the **CSL Delivery** (`241`) and **Identity** (`209`) org projects — see the "Adding the issue to GitHub Projects" section of [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md).

Do not apply a `task` label — the native type replaces it.

When you write the body, **link in-repo files as clickable GitHub blob URLs**, not plain-text paths. See the "Linking files in issue bodies" section of [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md).

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
<Exact command to run to confirm the task is complete, e.g., `mvn test -pl csl-domain -Dtest=PolicyVersionRepositoryTest`>

## Additional Context
<Related ADRs, deployment strategy relevance, links to sibling tasks, design notes.>
```

### 5. Update the parent feature (if applicable)

If this task has a parent feature, link it as a native GitHub sub-issue (done in step 4). The parent feature's body can also keep an Implementation Plan section for human readability, but the sub-issue link is the source of truth that GitHub uses to render progress and hierarchy.

If you keep the Implementation Plan section in the parent body, edit it to add this task:

```markdown
## Implementation Plan
- [ ] #<task-1-number> — <short description>
- [ ] #<task-2-number> — <short description>
- [ ] #<this-task-number> — <short description>
```

### 6. Flag ADR-shaped decisions

If the task introduces a port/adapter/SPI, picks between viable approaches, or establishes a convention that other tasks will follow, point the user at the ADR workflow (`/adr` in Claude Code, or [adr.md](adr.md) for other agents). Tasks that just implement the mechanical work of an already-recorded decision don't need a fresh ADR — link the existing one in the Additional Context section instead.

### 7. Confirm with the user

Show the user the created issue URL and a one-line summary. If linked to a parent feature, mention that the parent has been updated. Ask if anything needs adjusting.

## Quality checks

Before creating, verify:
- [ ] The task is small enough to review in one sitting
- [ ] The "Why This Is Independently Mergeable" section gives a clear boundary
- [ ] Acceptance criteria are verifiable without human judgment
- [ ] The verification command is specific (not just "run all tests")
- [ ] If there's a parent feature, it is linked as a native sub-issue (GitHub UI shows the hierarchy), not only via body text
