# Documenting Code

This workflow creates or updates documentation for code, modules, features, and APIs. It applies when the user says "document this", "add docs for", or "write documentation for". It also applies when the user wants code-level documentation created or updated. Claude Code users can also run this workflow with `/docs`.

An ADR records a decision. It is not code documentation. For a decision, follow [adr.md](adr.md) (Claude Code: `/create-architecture-decision`).

## Process

### 1. Identify

Use the session context to find these three items:

- The subject to document (a class, module, feature, API, or pattern).
- The audience: developers of host applications, contributors, or operators.
- Whether a document already exists. If it does, update it. Do not duplicate it.

### 2. Choose the documentation type

| What | Where | Format |
|---|---|---|
| Public contract of a class, method, port, or SPI | Inline in source | Javadoc |
| How a host application wires, configures, or overrides CSL | `docs/adopters/` | Markdown guide |
| What is shipped today (rollout status) | arc42 §2.1 in [02-current-state.md](../architecture/02-current-state.md) | Update existing section |
| Components, modules, ports, policy model | arc42 §5 in [05-building-block-view.md](../architecture/05-building-block-view.md) | Update existing section |
| Runtime flows (for example login, token refresh, authorization check) | arc42 §6 in [06-runtime-view.md](../architecture/06-runtime-view.md) | Update existing section |
| Deployment topology | arc42 §7 in [07-deployment-view.md](../architecture/07-deployment-view.md) | Update existing section |
| Crosscutting concepts (for example logging, error handling, sessions, multi-tenancy) | arc42 §8 in [08-crosscutting-concepts.md](../architecture/08-crosscutting-concepts.md) | Update existing section |
| Risks, technical debts, open design questions | arc42 §10 in [10-technical-debts-risks.md](../architecture/10-technical-debts-risks.md) | Update existing section |
| New terms | arc42 §11 in [11-glossary.md](../architecture/11-glossary.md) | Add glossary entry |
| Agent harness | `.claude/docs/` and `AGENTS.md` | Update existing files |

The [architecture README](../architecture/README.md) lists all arc42 sections.

### 3. Write

Write all text in Simplified Technical English (STE) Plain mode. Use the `simple-english` skill (`.claude/skills/simple-english/SKILL.md`).

Javadoc:

- Document why and the contract, not how. The code shows how.
- Add `@param`, `@return`, and `@throws` to all public methods.
- For ports and SPIs, document what implementors must guarantee.

arc42:

- Update the existing section. Do not add a new top-level file.
- Several sections describe the target design, and their headings say "target". If you describe something that is not built yet, say so. Link to the [rollout status](../architecture/02-current-state.md#21-rollout-status-at-a-glance).
- Link to an ADR for the rationale. Do not repeat the rationale.

Adopter guide:

- Say what the capability does and when to use it.
- Give the configuration that it needs.
- Add a code example.
- List the limitations.

### 4. Update related documentation

After you write, make sure that these documents are current:

- arc42 §2.1, if the rollout status of a capability changes.
- `.claude/docs/architecture.md`, if the module structure changes.
- `AGENTS.md`, if the change affects how agents work in the repository.
- `README.md`, if the change is visible to users.
- `docs/adopters/`, if host applications must change their integration.
- [ports.md](../adopters/ports.md), if a port is added or its contract changes.

If the change is visible to host operators or end users, add a camunda-docs note to the PR description. See the User documentation section in `AGENTS.md`.

## Quality checks

- [ ] The text explains why, not only what.
- [ ] Make sure that no information is duplicated. Link to the existing text instead.
- [ ] Code examples compile and follow current conventions.
- [ ] Make sure that the related documentation is current.
- [ ] The text passes the self-check in the `simple-english` skill.
