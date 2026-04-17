---
name: bug
description: Use when the user reports a bug, says "track this bug", "this is broken", "the behavior should be X", or describes unexpected behavior they want fixed
---

# Track Bug

Create a GitHub issue from a short bug description that is **self-contained enough for a fresh agent session to pick up and deliver a complete fix without further conversation**.

## Process

### 1. Confirm what you know

From the current session context, identify what you already know about:
- What is broken
- What the expected behavior should be
- Where in the code the problem is (files, classes, methods, line numbers)
- How to reproduce it
- What a fix looks like

### 2. Fill gaps — ask only what you must

If any of these are missing and you cannot determine them from the current session, ask the user. Batch your questions into a single message. Do not ask for information you can determine yourself from the codebase.

**You MUST know before creating the issue:**
- What is broken (summary)
- What should happen instead (expected behavior)

**You SHOULD know (investigate the codebase if needed):**
- Where the bug is (file paths, class names, method names — be specific)
- How to trigger it (steps or a test description)
- What verification command confirms the fix (e.g., `mvn test -pl sgf-domain -Dtest=SpecificTest`)
- What related code or patterns exist that the fix should follow

**Do NOT ask the user for:**
- Code locations you can find by reading the codebase
- Reproduction steps you can infer from the conversation
- Acceptance criteria you can derive from the expected behavior

### 3. Create the issue

Use `gh issue create` with the bug template. Every field should give a cold-start agent what it needs.

```
gh issue create \
  --label "bug" \
  --title "<concise title>" \
  --body "<body>"
```

**Body structure:**

```markdown
## Summary
<One or two sentences — what is broken.>

## Expected Behavior
<What should happen.>

## Actual Behavior
<What happens instead.>

## Location in Code
<Specific file paths, class names, method names, line numbers.>
<Reference any patterns the fix should follow.>

## Steps to Reproduce
<How to trigger the bug. Prefer "write a test that does X and expects Y" over prose.>

## Acceptance Criteria
- [ ] <Verifiable criterion — a test that should pass, a behavior that should be observable>
- [ ] <Each criterion must be checkable by an agent without human judgment>

## Verification
<Exact command to run to confirm the fix, e.g., `mvn test -pl sgf-domain -Dtest=PolicyApplyServiceTest`>

## Additional Context
<Related ADRs, deployment strategy relevance, links to related issues.>
```

### 4. Confirm with the user

Show the user the created issue URL and a one-line summary. Ask if anything needs adjusting.

## Quality checks

Before creating, verify:
- [ ] A fresh agent reading only this issue could find the bug location without exploring
- [ ] Acceptance criteria are verifiable without human judgment
- [ ] The verification command is specific (not just "run all tests")
- [ ] Location in Code includes file paths, not just module names
