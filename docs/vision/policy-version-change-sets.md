---
status: Proposed
---

# PolicyVersion commits with full-policy propagation (iteration one)

> **Not yet implemented.** This document was moved out of `docs/adr/` — where it was originally
> recorded as ADR-0001 — because no code implements it yet, planned for Camunda 8.11. As part of
> the same consolidation, ADR-0001 was reassigned to an unrelated, currently-Accepted decision, so
> use this file's git history, not that ADR, to trace this document's origin. When work on this
> topic actually begins, revisit this document and promote it back into `docs/adr/` as a new,
> sequentially-numbered ADR (do not reuse the old number).

## Status

Proposed

## Context

- Hub propagates policy updates to 1-N existing Orchestration Clusters.
- In SaaS, one shared Hub instance serves multiple organizations, so Hub-side policy persistence must be scoped by organization as well as cluster.
- The primary requirement is current-state correctness, not historical reconstruction.
- New OC joins are expected to be rare and only require the current state.

## Decision

We choose Option 1.

- Use `PolicyVersion` as a delivery-neutral organization + cluster-scoped commit in Hub (`version_number`).
- In iteration one, always propagate full policy payloads (`POLICY_SNAPSHOT`) to OCs for every new `PolicyVersion`.
- Keep stable entity IDs.
- Persist full-entity revisions (`EntityRevision`) for each change (including tombstones for deletes).
- Build `POLICY_SNAPSHOT` from latest non-deleted revisions per entity/scope up to a target version.
- Keep `PolicyVersionChange`/`base_version` optional and reserved for a potential later diff optimization, not required for first-iteration apply.

## Options considered

### Option 2 – Incremental diff propagation

- Pros: smaller payloads and less repeated apply work on OC side for small policy changes.
- Cons: higher complexity in dispatcher/apply flow (`base_version` chains, gap handling, re-sync behavior, and diff reconstruction).
- Not chosen for iteration one to keep delivery and OC apply deterministic and low risk.
- Can be introduced in a later iteration as an optimization if payload size/throughput metrics justify it.

### Option 3 – Event sourcing style (full-resource events)

- Pros: strong audit trail and replay capabilities.
- Cons: higher complexity and operational overhead.
- Not chosen because replay/history is not a core requirement.


## Consequences

- OC apply path is simpler: replace projection with full snapshot per `PolicyVersion` and keep idempotency by `policyVersionId`.
- No patch/merge ambiguity and no base-version mismatch handling in iteration one.
- Higher payload size and potentially higher network/DB write load; rollout needs payload limits, batching, and observability.
- Diff-based propagation remains a deliberate future optimization that can be added if operational metrics justify it.
