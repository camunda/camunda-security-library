# Creating Epic Issues

This workflow creates GitHub epic issues that **group a coherent set of tasks within a parent feature**. An epic represents a phase or milestone — larger than a single task, but scoped enough that it has a clear completion condition when all its tasks are done.

It applies when a user says "create an epic for phase X", "track this phase", or when breaking a feature into phases.

Claude Code users: this workflow is also available as `/epic`.

## What makes something an epic (vs a feature or task)

- **Feature** — the user-facing outcome ("Hub fully adopts CSL"). Delivered across multiple epics.
- **Epic** — a coherent phase of work within the feature ("P2: Migrate read-only AuthenticationService call sites"). Done when all its tasks are complete.
- **Task** — a single, independently mergeable unit of work ("Migrate call sites in modeler-public-api-common").

An epic is always a child of a feature. It must have a clear completion condition — a state where someone could say "this phase is done" — and its scope must not be redundant with sibling epics.

## Process

### 1. Confirm what you know

From the current session context, identify what you already know about:
- What phase or milestone this epic represents
- Which parent feature issue it belongs to
- What the completion condition looks like
- What tasks will deliver this epic (even if they don't exist as issues yet)
- Whether this epic has a runtime impact (no-op refactor vs. behavior change)

### 2. Fill gaps — ask only what you must

**You MUST know before creating the issue:**
- What phase this epic represents (summary)
- Which parent feature issue links here
- What "done" looks like (completion condition)

**You SHOULD know (investigate the codebase if needed):**
- Runtime classification — is this a no-op refactor or a behavior change?
- What CSL-side work (if any) must land before this epic can start
- What the expected PR cadence looks like (one large PR vs. several surgical PRs)
- Any dependencies on sibling epics

**Do NOT ask the user for:**
- Task breakdowns you can derive from the plan document
- Implementation details you can determine from the architecture

### 3. Create the issue

Use `gh issue create` with the epic template.

```
gh issue create --title "<concise title>" --body "<body>"
```

After creation:

1. Set the native issue type to `Epic` — see [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md) for the command.
2. Link it as a native sub-issue of its parent feature — also covered in [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md).

Do not apply an `epic` label — the native type replaces it.

When you write the body, **link in-repo files as clickable GitHub blob URLs**, not plain-text paths. See the "Linking files in issue bodies" section of [github-issue-operations.md](https://github.com/camunda/camunda-security-library/blob/main/docs/workflows/github-issue-operations.md).

**Body structure:**

```markdown
## Summary
<One or two sentences — what phase this is and what it achieves.>

## Parent Feature
<Link to parent feature issue — e.g., #NNN — Hub adopts CSL>

## Runtime Classification
<One of: `No-op refactor` | `Behavior change (isolated)` | `Behavior change (broad — one-way door)`. Add a brief explanation of why.>

## Completion Condition
<What "done" looks like. A state someone can verify: "all X call sites use Y", "class Z is deleted", "feature flag removed".>

## Scope
**In scope:**
- <What this epic covers>

**Out of scope:**
- <What this epic explicitly defers — to another epic or out of scope entirely>

## CSL Coordination
<Any CSL-side work that must land before this epic can start. Link issues. Write "None — hub-local adapters are sufficient" if there are no upstream blockers.>

## Implementation Plan
<Checkboxes linking to task issues that will deliver this epic. Populated as tasks are created via the task workflow. Leave the list empty at epic creation time if the breakdown isn't known yet.>
- [ ] <Linked via `#<task-number>` as tasks are created>

## Additional Context
<Related ADRs, deployment strategy relevance, links to plan documents, PR cadence notes.>
```

### 4. Break into tasks

After creating the epic, use the task workflow (`/task` in Claude Code, or `docs/workflows/tasks.md`) to create and link child tasks. Each task becomes a sub-issue of this epic. Link tasks as native sub-issues, not just body mentions.

### 5. Update the parent feature

After creating the epic, link it as a native GitHub sub-issue of the parent feature. Also update the parent feature's Implementation Plan section to reference this epic.

### 6. Confirm with the user

Show the epic URL and a one-line summary. Ask if the scope or completion condition needs adjusting before creating child tasks.

## Quality checks

Before creating, verify:
- [ ] A fresh agent could read this issue and understand what phase it covers without referencing external documents
- [ ] The completion condition is verifiable — not "work is done" but a specific observable state
- [ ] CSL Coordination is explicitly addressed (even if the answer is "none required")
- [ ] Runtime classification is labeled — one of `No-op refactor`, `Behavior change (isolated)`, or `Behavior change (broad — one-way door)`
- [ ] The parent feature is linked as a native sub-issue relationship, not only in body text
