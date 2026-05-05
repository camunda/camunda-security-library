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

## Git Hooks

Three hooks ship with the project in `.mvn/hooks/` and run directly from that directory — git is pointed at the path by `core.hooksPath`, which Maven sets during the `initialize` phase. No hook files are copied into `.git/hooks/`. Editing a hook is a normal code change with regular git history.

| Hook | What it does |
|---|---|
| `pre-push` | Runs `./mvnw -T 1C verify -DskipITs` and blocks the push on failure. |
| `pre-commit` | Runs `spotless:apply` on staged `.java` files and re-stages the results. Aborts if a partially-staged file is reformatted, to avoid silently swallowing unstaged hunks. No-op until `spotless-maven-plugin` is configured. |
| `commit-msg` | Enforces Conventional Commits on the header line, including the 100-char limit. Merge, revert, fixup, and squash commits are exempt. |

**Bypass a single git operation:** `git push --no-verify` / `git commit --no-verify`.

**Skip all CSL hooks for the current shell:** `export CSL_SKIP_HOOKS=1`.

**Do not configure `core.hooksPath` at all:** run Maven with `-Dskip.hooks=true`, or set `CI` in your environment. Useful for CI and scripted setups that shouldn't touch developer config.

## Pre-Commit Verification

Run the full verification sequence before every commit:

1. Code must compile cleanly
2. All tests must pass
3. No flaky tests — if a test fails intermittently, fix it before committing. Do not skip or retry.
