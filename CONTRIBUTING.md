# Contributing to the Camunda Security Library

## Getting Started

This project is set up for AI-assisted development. Whether you're working with Claude, Copilot, Gemini, Cursor, or another AI agent, the repository includes structured context to help agents understand the project and produce quality work.

### Project Context for AI Agents

| File | Purpose | Audience |
|---|---|---|
| `AGENTS.md` | Agent-neutral project overview: stack, architecture, conventions, workflow, issue creation guidance | All AI agents |
| `CLAUDE.md` | Claude-specific entry point with references to detailed docs | Claude Code |
| `.claude/docs/` | Detailed architecture, conventions, commands, workflow, and guardrails | Claude Code (referenced via `@`) |

If you're using an agent other than Claude, point it at `AGENTS.md` — it's self-contained.

### AI-Assisted Workflows

Common AI-assisted workflows are documented in `docs/workflows/` — these are agent-neutral process guides any AI tool can follow:

| Workflow | File | What it does |
|---|---|---|
| Creating bug issues | `docs/workflows/bug-issues.md` | Produces a structured GitHub bug issue from a short description. Enriches it with code locations, reproduction steps, and verifiable acceptance criteria so a fresh session can fix it without further conversation. |
| Creating feature issues | `docs/workflows/feature-issues.md` | Produces a structured GitHub feature issue from a short description. Includes motivation, scope boundaries, implementation location, and acceptance criteria so a fresh session can implement it cold. |
| Creating task issues | `docs/workflows/tasks.md` | Produces a small, self-contained, independently mergeable task issue. A task can stand alone, or be one of several that together deliver a feature. |
| Documenting code | `docs/workflows/documenting-code.md` | Creates or updates documentation — Javadoc, module READMEs, feature guides, or ADRs — and ensures related docs stay in sync. |

**Claude Code users:** these workflows are also available as slash commands via `.claude/skills/`:

| Command | Workflow |
|---|---|
| `/bug` | Creating bug issues |
| `/feature` | Creating feature issues |
| `/task` | Creating task issues |
| `/docs` | Documenting code |

**Users of other AI tools (Copilot, Cursor, Gemini, etc.):** point your agent at the relevant file in `docs/workflows/` when you want it to follow one of these workflows.

### Features vs tasks

- **Feature** — a user-facing outcome ("users should be able to bulk-assign roles"). Often too large to deliver in a single reviewable PR.
- **Task** — a small, self-contained, independently mergeable unit of implementation work. Can be standalone, or one of several tasks that together deliver a feature.

When a feature is too large to land in a single small PR, break it into tasks. Each task must be safe to merge on its own — either because it stands alone, or because it lands behind a boundary (no caller yet, feature flag, internal only, additive change) until the parent feature is complete.

### Working on an Issue

Issues created via `/bug` and `/feature` are designed to be **self-contained** — a fresh agent session should be able to resolve them without prior context. To work on one, start a new session and point the agent at the issue:

> "Work on https://github.com/camunda/camunda-security-gateway/issues/123"

The agent will read the issue, follow the acceptance criteria, and verify against the stated verification command. If the issue is missing information the agent needs, that's a signal the issue itself should be improved — update the issue rather than handing the context verbally.

### Issue Templates

GitHub issue templates (`.github/ISSUE_TEMPLATE/`) mirror the structure the AI commands produce:

- **Bug Report** (`bug.yml`) — summary, expected/actual behavior, code location, reproduction steps, acceptance criteria
- **Feature Request** (`feature.yml`) — summary, motivation, expected behavior, scope/boundaries, code location, acceptance criteria, implementation plan
- **Task** (`task.yml`) — summary, parent feature (if any), why independently mergeable, scope, code location, acceptance criteria, verification

These templates work for both human-authored and AI-authored issues.

## Development Workflow

### Branching

Format: `<type>/<short-description>` (e.g., `feat/add-policy-model`, `fix/null-pointer-on-apply`)

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`

### Commits

Conventional Commits format: `<type>(<scope>): <subject>`

### Pull Requests

- PR title follows Conventional Commits format
- Squash-merge to keep main history clean
- Link relevant issues in the PR description

### Git Hooks

Three hooks live in `.mvn/hooks/` and are checked into the repository. On `./mvnw initialize` (triggered by any higher phase — `verify`, `test`, `install`), Maven runs `git config --local core.hooksPath .mvn/hooks`, which tells git to execute hooks from the in-tree path directly. No files are copied into `.git/hooks/`.

| Hook | What it does |
|---|---|
| `pre-push` | Runs `./mvnw -T 1C verify -DskipITs` and blocks the push on failure. |
| `pre-commit` | Runs `spotless:apply` on staged `.java` files and re-stages reformatted files. Aborts if a partially-staged file is reformatted. |
| `commit-msg` | Enforces Conventional Commits on the subject line (see `.claude/docs/workflow.md#commit-message-format`). |

**Bypass a single git operation:** `git commit --no-verify` / `git push --no-verify`.

**Skip all CSL hooks for the current shell:** `export CSL_SKIP_HOOKS=1`.

**Do not configure `core.hooksPath` at all:** run Maven with `-Dskip.hooks=true`, or set `CI` in your environment.

**Opt out for your own checkout:** `git config --local --unset core.hooksPath` after running Maven. You can also point `core.hooksPath` at a different directory if you maintain your own hooks.

`git` must be on your `PATH` for the `initialize` step to succeed. This is a normal prerequisite for contributing to a git-managed project.

### Architecture Decision Records

Significant design choices are documented as ADRs in `docs/adr/`. When in doubt, write one — a short ADR capturing the reasoning is more valuable than no record at all. See `.claude/docs/workflow.md` for guidance on when to write an ADR.

## Releases

Releases are cut by the [`release` workflow](.github/workflows/release.yml), dispatched manually from the GitHub Actions tab. The workflow runs `maven-release-plugin`, **publishes to Camunda's internal Maven repository** (visible to internal consumers immediately), **stages a deployment on Sonatype Central** (an operator publishes it manually for external consumers — see below), creates a GitHub Release, and (in canary mode) opens a mergeback PR. Concurrent dispatches are serialized — never cancelled — so an accidental second dispatch queues behind the in-flight one.

### Dispatching a release

Go to **Actions → release → Run workflow** and fill in:

| Input | Required | Description |
|---|---|---|
| `releaseVersion` | yes | Version to release, e.g. `0.1.0` |
| `nextDevelopmentVersion` | yes | Next snapshot, e.g. `0.2.0-SNAPSHOT` |
| `baseBranch` | no | Base to cut a new `release/<version>` canary from. Mutually exclusive with `releaseBranch`. Defaults to the dispatch ref (typically `main`) when both are empty. |
| `releaseBranch` | no | Existing branch to release from (e.g. a maintenance branch for a patch). Mutually exclusive with `baseBranch`. No mergeback PR is opened in this mode. |
| `dryRun` | no | Defaults to **true**. Set to false for an actual release. A dry run skips git pushes, Maven publishing, canary push, and PR creation. |

> **Always do a dry run first.** `dryRun=true` is the default for a reason — it exercises the whole workflow without side effects.

### Modes

- **Canary mode** (default — `baseBranch` set or both inputs empty): the workflow creates a fresh `release/<releaseVersion>` branch off the base, runs the release on it, and opens a mergeback PR back to the base. Once the canary is cut, it is a fixed branch unaffected by subsequent merges to the base — so concurrent merges after that point can't interleave with the version commits or tag. (There is a small window between dispatch and canary creation — secret import, checkout — where a merge to the base can still be picked up; if that matters for a given release, dispatch when the base is quiet.)
- **Existing-branch mode** (`releaseBranch` set): the workflow releases from the branch you provide. No canary is created and no mergeback PR is opened. Use this for patch releases on a maintenance branch, or to resume a release on an existing canary (see Recovery below).

### After a successful release

1. The tag and GitHub Release are published. The artifact is **published to Camunda's internal Maven repository** (immediately visible to internal consumers) and **staged on Sonatype Central** (not yet visible to external consumers).
2. **Publish the staged release on Sonatype Central.** Log in to <https://central.sonatype.com/publishing> with the Camunda credentials from Keeper, find the staged deployment for `io.camunda:camunda-security-library:<version>`, verify the contents look right, and click **Publish**. Once published, the artifact is final and cannot be unpublished.
3. In canary mode, a mergeback PR is opened from `release/<version>` into the base branch. Review and merge it to bring the version-bump commits back to the base.
4. **CI on the mergeback PR:** GitHub does not run workflows on PRs opened via `GITHUB_TOKEN`. To trigger CI on the mergeback PR, push an empty commit (`git commit --allow-empty -m "ci: trigger"`) or close-and-reopen the PR.

### Recovery from a failed release (canary mode)

> **If the run failed before the canary was created** (input validation, the origin-existence check, secret import, or checkout) just re-dispatch in canary mode — there's nothing to clean up. The rest of this section assumes a canary exists.

The canary branch is intentionally left on origin when a run fails — it carries the partial state and is what you'll resume from. **There's no need to delete and recreate the canary**; the published-side state (tag, GitHub Release, Sonatype staging) is what blocks a same-version retry, not the canary's git history. `maven-release-plugin` will re-bump the pom from whatever version is current on the canary.

1. **Clean up the published-side state**, depending on how far the failed run got:

   | Failed during/before | What's left | What to clean up |
   |---|---|---|
   | `release:prepare` | Version commits on canary; **the tag may also be on origin** if prepare failed during/after the push step | Check with `git ls-remote origin refs/tags/<version>`; if present, delete: `git push origin :refs/tags/<version>` |
   | `release:perform` (before staging upload) | Above + tag definitely pushed to origin | Delete the tag: `git push origin :refs/tags/<version>` |
   | `release:perform` (after staging upload) | Above + staged deployment on Sonatype Central | Above + **Drop** the staged deployment at <https://central.sonatype.com/publishing> (Camunda creds in Keeper) |
   | `Create GitHub Release` or later | Above + GitHub Release exists | Above + delete the GitHub Release: `gh release delete <version>` |
   | After you clicked **Publish** on Sonatype Central | Artifact is final on Maven Central | **Stop.** Sonatype Central does not allow unpublishing — pick a new version, or finish the remaining workflow steps manually. |

   The staged-deployment **Drop** is the critical step — without it, a same-version retry will fail when `release:perform` tries to upload to Central again.

2. **Push any fix commits** to `release/<version>` if needed.

3. **Re-dispatch the workflow** with `releaseBranch=release/<version>`. The resume runs in existing-branch mode, which skips canary creation and **does not open a mergeback PR**.

4. If the original run never reached the `Open mergeback PR` step, open the PR by hand after the resume completes:

   ```
   gh pr create --base <baseBranch> --head release/<version> \
     --title "chore(release): merge back <version> into <baseBranch>"
   ```

### Recovery from a failed release (existing-branch mode)

In `releaseBranch` mode (typically a patch release on a maintenance branch), there is no canary — the failed run may have left version commits and/or a tag directly on the branch you're releasing from. **Pause and assess before cleaning up**: the right sequence depends on what the failure left behind. Likely steps:

- Inspect the maintenance branch for stray version-bump commits and decide whether to revert them, force-push to drop them, or land a follow-up commit and re-run.
- Apply the same published-side cleanup as canary mode (drop staged deployment, delete tag, delete GitHub Release if created).
- Re-dispatch the workflow with the same `releaseBranch` once the branch is in a sane state.

## Architecture

The CSL uses hexagonal (ports and adapters) architecture. The domain has zero framework dependencies. See `AGENTS.md` for a complete overview or `.claude/docs/architecture.md` for detailed module boundaries and data flows.

## License

This project is licensed under the [Camunda License](https://legal.camunda.com/).
