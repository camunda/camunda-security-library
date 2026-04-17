# Contributing to Security Gateway Framework

## Getting Started

This project is set up for AI-assisted development. Whether you're working with Claude, Copilot, Gemini, Cursor, or another AI agent, the repository includes structured context to help agents understand the project and produce quality work.

### Project Context for AI Agents

| File | Purpose | Audience |
|---|---|---|
| `AGENTS.md` | Agent-neutral project overview: stack, architecture, conventions, workflow, issue creation guidance | All AI agents |
| `CLAUDE.md` | Claude-specific entry point with references to detailed docs | Claude Code |
| `.claude/docs/` | Detailed architecture, conventions, commands, workflow, and guardrails | Claude Code (referenced via `@`) |

If you're using an agent other than Claude, point it at `AGENTS.md` — it's self-contained.

### AI-Assisted Commands

The repository includes Claude Code commands (`.claude/commands/`) that streamline common workflows. These can be invoked as slash commands in Claude Code:

| Command | Trigger | What it does |
|---|---|---|
| `/bug` | "Track this bug", "this is broken", "the behavior should be X" | Creates a structured GitHub issue from a short bug description. Enriches it with code locations, reproduction steps, and verifiable acceptance criteria so a fresh session can fix it without further conversation. |
| `/feature` | "We should be able to", "add support for", "I want to be able to" | Creates a structured GitHub issue from a short feature description. Includes motivation, scope boundaries, implementation location, and acceptance criteria so a fresh session can implement it cold. |
| `/docs` | "Document this", "add docs for", "write documentation for" | Creates or updates documentation — Javadoc, module READMEs, feature guides, or ADRs — and ensures related docs stay in sync. |

These commands are designed for a two-step workflow:
1. **Quick capture** — describe what you need in a short sentence, the agent creates a rich, self-contained issue
2. **Cold-start resolution** — in a new session, point the agent at the issue URL and it delivers a complete result

### Issue Templates

GitHub issue templates (`.github/ISSUE_TEMPLATE/`) mirror the structure the AI commands produce:

- **Bug Report** (`bug.yml`) — summary, expected/actual behavior, code location, reproduction steps, acceptance criteria
- **Feature Request** (`feature.yml`) — summary, motivation, expected behavior, scope/boundaries, code location, acceptance criteria

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

### Architecture Decision Records

Significant design choices are documented as ADRs in `docs/adr/`. When in doubt, write one — a short ADR capturing the reasoning is more valuable than no record at all. See `.claude/docs/workflow.md` for guidance on when to write an ADR.

## Architecture

The SGF uses hexagonal (ports and adapters) architecture. The domain has zero framework dependencies. See `AGENTS.md` for a complete overview or `.claude/docs/architecture.md` for detailed module boundaries and data flows.

## License

This project is licensed under the [Camunda License](https://legal.camunda.com/).
