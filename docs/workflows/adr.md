# Writing ADRs

This workflow creates Architecture Decision Records (ADRs) in `docs/adr/`. CSL follows the Camunda org skill `create-architecture-decision` with the overrides in this file.

In Claude Code, use `/create-architecture-decision`. The skill comes from the `camunda/actora` plugin marketplace. Its text is at [SKILL.md](https://github.com/camunda/actora/blob/main/functions/engineering/skills/create-architecture-decision/skills/create-architecture-decision/SKILL.md).

Other agents must read and follow the linked skill text, with the CSL overrides below. This file is the source for agents other than Claude.

## Org format in short

The org skill defines the ADR shape. This summary is not a copy. Read the skill for the full rules.

- The header has these fields: DRI, Status, Purpose, Audience.
- The sections are Context, Decision, optional Alternatives considered, Consequences, and Source.
- The Decision section lists numbered decisions: D1, D2, and so on.
- The process has four steps. First, write a review summary. Second, post the full draft inline. Third, wait for approval. Fourth, write the file.

## When an ADR is required

An ADR records a fundamental, lasting architectural decision. If the decision is not final, do not write the ADR yet.

Write an ADR when a change does one of these things:

- Adds a new Maven module, or a new public contract (SPI) that host applications implement.
- Chooses between viable architectural approaches.
- Changes how deployment strategies, policy propagation, authentication, or authorization work.
- Adds or replaces a runtime dependency.
- Alters data flow, storage patterns, or persistence shape.
- Establishes a project-wide convention, for example for naming, layering, error handling, or packaging.

Do not write an ADR for these changes:

- Bug fixes that do not change the design.
- Style, formatting, or rename-only changes.
- Internal refactors that keep all public behavior and set no new convention.

## CSL overrides on the org skill

- Location: `docs/adr/`.
- Filename: `NNNN-title.md`. CSL has no release segment, unlike the org filename `NNNN-VVV-title.md`.
- Number: use the highest existing number plus one. If two PRs use the same number, the second PR to merge changes its own number.
- Header fields, in this order: `**DRI**`, `**Deciders**`, `**Status**`, `**Purpose**`, `**Audience**`.
- `**Deciders**` lists the people who agreed the change.
- `**Status**` has the form `Accepted (<CSL version>)`, for example `Accepted (1.3)`.
- New ADRs have no YAML frontmatter and no `## Status` section. Older ADRs keep their format.
- Language: STE Plain mode. See the Writing style section in [AGENTS.md](../../AGENTS.md). Field labels and decision headlines use bold as structure. The prose under them follows STE.
- Index: add an entry to §9.1 of [09-architecture-decisions.md](../architecture/09-architecture-decisions.md). CSL has no README table.
- Supersession: when an ADR supersedes another ADR, change the Status of the old ADR to `Superseded by ADR-NNNN`. This is the only substantive edit that you can make to a decided ADR. See [guardrails.md](../../.claude/docs/guardrails.md).
- Cross-references: link from the new ADR to related ADRs. Do not add back-links to decided ADRs. The only exception is the `Superseded by` Status above. This replaces the org rule that requires links in both directions.
- Renumbering: never renumber existing ADRs. The org rule that renumbers later ADRs does not apply, because CSL filenames have no release segment. The consolidation exception below is the only case.
- PR: link the new ADR from the PR description.

## ADRs are immutable

Decided ADRs are historical records. Do not change them in substance. If a team must revisit a decision, write a new ADR that supersedes the old one. Then change the Status of the old ADR to `Superseded by ADR-NNNN`. You can make editorial fixes, for example typos, link repair, and terminology normalization. The fix must keep the original decision and rationale exactly.

One exception applies to ADR numbers. A periodic consolidation can merge superseded or amended ADRs into one current-truth record. It can also renumber the remaining ADRs to close the gaps. [#622](https://github.com/camunda/camunda-security-library/pull/622) did this first. A consolidation must be rare. It must explicitly suspend this immutability rule and then restore it, as #622 did. Do not renumber outside a declared consolidation.
