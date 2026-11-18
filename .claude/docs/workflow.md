# Workflow

## Branch Naming

Format: `<type>/<short-description>` (e.g., `feat/add-policy-model`, `fix/null-pointer-on-apply`)

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`

Branch names must be lowercase and hyphen-separated — no underscores.

## Commit Message Format

Conventional Commits format: `<type>(<scope>): <subject>`

- Header line (`<type>(<scope>): <subject>`): max 100 characters, imperative mood, no trailing period — aligns with [commitlint config-conventional `header-max-length`](https://github.com/conventional-changelog/commitlint/tree/master/%40commitlint/config-conventional#header-max-length)
- Body: wrap at 100 characters; explain *why*, not *what*
- Breaking changes: `BREAKING CHANGE:` footer required
- Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `build`, `perf`
- Scope is optional but encouraged (e.g., `feat(policy): add snapshot apply`)

## PR Process

- PR title must follow the Conventional Commits format
- Required before merge: CI checks green, no unresolved comments
- Squash-merge to keep main history clean
- Exception: release mergeback PRs (`chore(release): merge back ...`) use a merge commit. The release workflow sets this with auto-merge. Do not squash or rebase them. The release tag must stay reachable from `main`.
- Link relevant issues in the PR description

## Releases

The release notes cover the range from the previous stable semver tag to the new tag. For example, the notes for 1.3.0 list the changes since 1.2.2. The release workflow finds the previous tag by version order, not by git history.

## Architecture Decision Records

An ADR records a fundamental, lasting architectural decision. The process, the trigger list, and the CSL overrides are in [`docs/workflows/adr.md`](../../docs/workflows/adr.md). In Claude Code, use `/create-architecture-decision`.

## Git Hooks

Three hooks ship with the project in `.mvn/hooks/` and run directly from that directory — git is pointed at the path by `core.hooksPath`, which Maven sets during the `initialize` phase. No hook files are copied into `.git/hooks/`. Editing a hook is a normal code change with regular git history.

| Hook | What it does |
|---|---|
| `pre-push` | Runs `./mvnw -T 1C verify -DskipITs` and blocks the push on failure. |
| `pre-commit` | Runs `spotless:apply` on staged `.java` files and re-stages the results. Aborts if a partially-staged file is reformatted, to avoid silently swallowing unstaged hunks. |
| `commit-msg` | Enforces Conventional Commits on the header line, including the 100-char limit. Merge, revert, fixup, and squash commits are exempt. |

**Bypass a single git operation:** `git push --no-verify` / `git commit --no-verify`.

**Skip all CSL hooks for the current shell:** `export CSL_SKIP_HOOKS=1`.

**Do not configure `core.hooksPath` at all:** run Maven with `-Dskip.hooks=true`, or set `CI` in your environment. Useful for CI and scripted setups that shouldn't touch developer config.

## Pre-Commit Verification

Run the full verification sequence before every commit:

1. Code must compile cleanly
2. All tests must pass
3. No flaky tests — if a test fails intermittently, fix it before committing. Do not skip or retry.
4. Code must be formatted — the pre-commit hook runs `spotless:apply` automatically on staged `.java` files. Do not skip it (`--no-verify`).
