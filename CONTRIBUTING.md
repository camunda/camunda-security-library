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

## Architecture

The CSL uses hexagonal (ports and adapters) architecture. The domain has zero framework dependencies. See `AGENTS.md` for a complete overview or `.claude/docs/architecture.md` for detailed module boundaries and data flows.

## License

This project is licensed under the [Camunda License](https://legal.camunda.com/).
