# Workflow

## Branch Naming

Format: `<type>/<short-description>` (e.g., `feat/add-policy-model`, `fix/null-pointer-on-apply`)

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`

Branch names must be lowercase and hyphen-separated — no underscores.

## Commit Message Format

Conventional Commits format: `<type>(<scope>): <subject>`

- Subject line: max 72 characters, imperative mood, no trailing period
- Body: wrap at 100 characters; explain *why*, not *what*
- Breaking changes: `BREAKING CHANGE:` footer required
- Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`
- Scope is optional but encouraged (e.g., `feat(policy): add snapshot apply`)

## PR Process

- PR title must follow the Conventional Commits format
- Required before merge: CI checks green, no unresolved comments
- Squash-merge to keep main history clean
- Link relevant issues in the PR description

## Architecture Decision Records

When a change involves a significant design choice, create an ADR in `docs/adr/`. Err on the side of writing one — a short ADR that captures the reasoning is far more valuable than no record at all.

**Write an ADR when:**
- Introducing a new module, port, or adapter
- Choosing between multiple viable approaches
- Changing how deployment strategies, policy propagation, or authorization work
- Adding or replacing a dependency
- Altering data flow or storage patterns

**Do not write an ADR for:**
- Bug fixes that don't change design
- Style or formatting changes

Note: even when following an established pattern, if the decision to do so was deliberate and worth recording, write an ADR. The value is in documenting that a conscious choice was made, not just in comparing alternatives.

Number ADRs sequentially. Check `docs/adr/` for the latest number.

## Pre-Push Hook

A pre-push git hook will enforce quality gates before code reaches the remote. The hook will be auto-installed via Maven on first build. Details will be documented here once the build tooling is in place.

## Pre-Commit Verification

Run the full verification sequence before every commit:

1. Code must compile cleanly
2. All tests must pass
3. No flaky tests — if a test fails intermittently, fix it before committing. Do not skip or retry.
