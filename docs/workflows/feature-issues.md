# Creating Feature Issues

This workflow creates GitHub feature issues that are **self-contained enough for a fresh agent session to pick up and deliver a complete implementation without further conversation**.

It applies when a user says "we should be able to", "add support for", "I want to be able to", or describes functionality that doesn't exist yet.

Claude Code users: this workflow is also available as `/feature`.

## Process

### 1. Confirm what you know

From the current session context, identify what you already know about:
- What should be possible (the capability)
- Why it's needed (motivation, what problem it solves)
- What it looks like when it works (inputs, outputs, side effects)
- Where it fits in the codebase (modules, packages, existing patterns to follow)
- What is explicitly out of scope

### 2. Fill gaps — ask only what you must

If any of these are missing and you cannot determine them from the current session, ask the user. Batch your questions into a single message. Do not ask for information you can determine yourself from the codebase.

**You MUST know before creating the issue:**
- What the feature does (summary)
- What it looks like when it works (expected behavior)

**You SHOULD know (investigate the codebase if needed):**
- Why it's needed (motivation — helps the implementing agent make judgment calls)
- Where it should be implemented (modules, packages, new files needed)
- What existing code to follow as a pattern (specific classes, not just "follow hex architecture")
- What is out of scope (prevents the implementing agent from over-building)
- What verification command confirms it works

**Do NOT ask the user for:**
- Implementation details you can determine from the architecture
- Which module something belongs in (the architecture docs tell you)
- What patterns to follow (the existing codebase tells you)

### 3. Create the issue

Use `gh issue create` with the feature template. Every field should give a cold-start agent what it needs.

```
gh issue create \
  --label "enhancement" \
  --title "<concise title>" \
  --body "<body>"
```

**Body structure:**

```markdown
## Summary
<One or two sentences — what should be possible.>

## Motivation
<Why this is needed. What problem it solves or workflow it enables.>

## Expected Behavior
<What the feature looks like when it works. Be specific about inputs, outputs, side effects.>

## Scope and Boundaries
**In scope:**
- <What to build>

**Out of scope:**
- <What NOT to build — be explicit>

## Location in Code
<Where to implement. Specific modules, packages, new files to create.>
<Existing classes to extend or follow as patterns — name them specifically.>

## Acceptance Criteria
- [ ] <Verifiable criterion — a behavior that should work, a test that should pass>
- [ ] <Each criterion must be checkable by an agent without human judgment>
- [ ] <Include a criterion for not breaking existing behavior>

## Verification
<Exact command to run to confirm the feature works, e.g., `mvn test -pl sgf-domain -Dtest=BulkRoleAssignmentServiceTest`>

## Additional Context
<Related ADRs, deployment strategy relevance, links to related issues, design notes.>
```

### 4. Confirm with the user

Show the user the created issue URL and a one-line summary. Ask if anything needs adjusting.

## Quality checks

Before creating, verify:
- [ ] A fresh agent reading only this issue could implement the feature without exploring for patterns
- [ ] Scope and Boundaries explicitly states what is out of scope
- [ ] Location in Code names specific existing classes to follow as patterns
- [ ] Acceptance criteria include a "no regression" check
- [ ] The verification command is specific (not just "run all tests")
