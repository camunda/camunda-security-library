# Writing ADRs

This workflow creates Architecture Decision Records (ADRs) in `docs/adr/`. ADRs are historical records of design choices that capture **what was decided, who agreed it, why it was chosen, and what alternatives were rejected**, so future maintainers (and agents) can read the decision instead of guessing at intent from the code alone.

Claude Code users: this workflow is also available as `/adr`.

## Default to writing an ADR

ADR-writing is part of the standard implementation flow, not an optional add-on. When a change involves a design choice — even one that feels obvious — write an ADR alongside it. A short ADR confirming a deliberate choice is more valuable than no record.

**Write an ADR when:**

- Introducing a new module, port, adapter, or SPI
- Choosing between multiple viable approaches (even when one is clearly preferred)
- Changing how deployment strategies, policy propagation, authentication, or authorization work
- Adding or replacing a runtime dependency
- Altering data flow, storage patterns, or persistence shape
- Establishing a project-wide convention (naming, layering, error handling, packaging)
- Following an established pattern *deliberately* — write a short ADR confirming the choice was conscious, not accidental

**Do not write an ADR for:**

- Bug fixes that don't change design
- Style, formatting, or rename-only changes
- Internal refactors that preserve all public behaviour and don't establish a new convention

When in doubt, write one.

## Process

### 1. Confirm what you're recording

Before opening the editor, identify:

- The decision you're capturing (one sentence)
- The motivating constraint or problem
- The deciders — the people who agreed the change. For solo work, that's just the author; for cross-team work, list everyone whose agreement the decision relies on.
- The alternatives you considered and rejected
- The consequences — both positive and accepted trade-offs
- Which other ADRs are relevant (predecessors, supersessions, sibling decisions)

### 2. Pick the next number

Check `docs/adr/` for the highest existing number and add one. ADRs are numbered sequentially and never renumbered. If two PRs both add ADR-NNNN, the second to merge bumps to NNNN+1 in a follow-up commit.

### 3. Draft the ADR file

Create `docs/adr/NNNN-kebab-case-title.md`. Look at [`0009-web-app-authorization-spis.md`](../adr/0009-web-app-authorization-spis.md) and [`0010-admin-user-setup-spis.md`](../adr/0010-admin-user-setup-spis.md) as recent reference shapes.

Use the structure below. Match it exactly — readers and tooling rely on the shape.

```markdown
---
status: Accepted
---

# ADR-NNNN: <concise title — what's being decided>

**Deciders**: <comma-separated names of those who agreed the change>

## Status

Accepted | Proposed | Superseded by ADR-XXXX

## Context

<Why this decision is being made now. The constraint, the question, the prior state. Reference predecessor ADRs that scoped or deferred this. End the section with the core question this ADR answers.>

## Decision

<What was decided, in concrete terms. Names of new types, packages, methods. The activation/integration model.>

### Why these particular boundaries

<Bullet rationale for each non-obvious shape choice. Include why each alternative was rejected if relevant.>

### Default implementations and override boundaries

<Optional table when the ADR introduces SPIs or extension points.>

## Consequences

**Positive**

- <Each upside, especially the ones that make the alternatives less attractive.>

**Negative / accepted trade-offs**

- <Each downside or constraint the team has decided to live with.>

## Alternatives Considered

- **<Alternative 1>.** Rejected — <reason>.
- **<Alternative 2>.** Rejected — <reason>.
```

#### Notes on each field

- **`status` (frontmatter)** — `Accepted` for live decisions. `Proposed` only when the decision isn't final yet (rare; prefer not to open a PR until it is). `Superseded by ADR-XXXX` once a later ADR replaces this one.
- **Title** — phrase as the decision, not the topic ("Lift webapp authorization filter into CSL", not "Webapp authorization filter").
- **`Deciders`** — comma-separated names. Required for new ADRs from this workflow onward. Existing ADRs (0001–0010) predate this requirement and are not retroactively updated. For solo work, list just the author; for cross-team agreement, list everyone whose buy-in the decision relies on.
- **Context** — problem + question. End with one sentence that names the question this ADR answers, e.g. *"What SPI shape lets hosts plug in the web-app-id derivation without duplicating the filter?"*. Don't narrate process.
- **Decision** — concrete artefacts: type names, package locations, integration points. The reader should be able to map the ADR onto the code.
- **Consequences** — at least one accepted trade-off. If you can't think of one, the decision probably isn't substantive enough to warrant an ADR.
- **Alternatives Considered** — at least one entry. Forces you to articulate why this approach won.

### 4. Link the ADR from the work it accompanies

When the ADR accompanies a code change:

- Reference the ADR from the PR description.
- If the code introduces a new contract, link the ADR from the contract's class-level Javadoc or module README.
- If the ADR supersedes another, edit the predecessor's `Status` to `Superseded by ADR-NNNN`. This is the **only** allowed substantive edit to a decided ADR — see [`.claude/docs/guardrails.md`](../../.claude/docs/guardrails.md).

### 5. Confirm with the user

Show the user the file path of the new ADR and a one-line summary. If the deciders include anyone other than the author, confirm the names with the user before committing.

## Quality checks

Before committing, verify:

- [ ] `Deciders` line is present and lists everyone whose agreement the decision relies on.
- [ ] `Status` matches the actual state of the decision (`Accepted` is the default).
- [ ] Context ends with the question this ADR answers.
- [ ] At least one alternative is documented and rejected.
- [ ] Consequences include at least one accepted trade-off.
- [ ] Cross-references to related ADRs use clickable relative links (e.g. `[ADR-0009](0009-web-app-authorization-spis.md)`).
- [ ] No edits to existing decided ADRs except status changes and editorial fixes that preserve meaning.

## ADRs are immutable

Decided ADRs are historical records — do not substantively modify them. If a decision needs revisiting, write a new ADR that supersedes the old one and update the old one's `Status` to `Superseded by ADR-NNNN`. Editorial fixes (typos, link repair, terminology normalization) are permitted as long as they preserve the original decision and rationale exactly.
