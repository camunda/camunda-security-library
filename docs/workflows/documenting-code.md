# Documenting Code

This workflow creates or updates documentation for code, modules, features, or APIs.

It applies when a user says "document this", "add docs for", "write documentation for", or wants code-level documentation created or updated.

Claude Code users: this workflow is also available as `/docs`.

## Process

### 1. Identify what to document

From the current session context, determine:
- What is being documented (a class, module, feature, API, pattern, or decision)
- Who the audience is (developers consuming the library, contributors, operators)
- Whether documentation already exists that should be updated rather than duplicated

### 2. Determine the right documentation type

| What | Where | Format |
|---|---|---|
| Public API (class, method, interface) | Inline in source | Javadoc |
| Module purpose and usage | `README.md` in the module root | Markdown |
| Feature guide (how to use a capability) | `docs/features/` | Markdown |
| Architecture decision | `docs/adr/` | ADR format (see ADR section below) |
| Agent harness update | `.claude/docs/` and `AGENTS.md` | Update existing files |

### 3. Write the documentation

**Javadoc (public APIs):**
- Document the *why* and *contract*, not the *how* — the code shows how
- Include `@param`, `@return`, `@throws` for all public methods
- For ports and SPIs, document what implementors must guarantee

**Module README:**
- Purpose in one sentence
- How it fits in the architecture (which layer, what it depends on)
- Key classes and their roles
- How to test it

**Feature guide:**
- What the feature does and when to use it
- Configuration required
- Code example showing usage
- Edge cases or limitations

### 4. Update related documentation

After writing, check whether any of these need updating:
- `docs/adr/README.md` — if a new ADR was created
- `AGENTS.md` — if the change affects how agents should work with the codebase
- `.claude/docs/architecture.md` — if module structure changed
- `README.md` — if the change is user-facing

### ADR creation

To record an architecture decision, follow [adr.md](adr.md). In Claude Code, use `/create-architecture-decision`.

## Quality checks

Before finishing, verify:
- [ ] Documentation explains *why*, not just *what*
- [ ] No duplication of information that exists elsewhere
- [ ] Code examples compile and are consistent with current conventions
- [ ] Related docs are updated if affected
