## 1. Introduction and goals

> **Document structure:** Section 2 states current rollout status ([§2.1](./02-current-state.md#21-rollout-status-at-a-glance))
> and, as background, the pre-CSL identity architecture and its limitations. The arc42 target
> architecture begins at section 3.

This document describes the Unified Identity Architecture for Camunda Hub, Optimize, and
Orchestration Clusters in an arc42-style structure, part of which — authentication, and the OC
authorization read path — has already shipped (see [§2.1](./02-current-state.md#21-rollout-status-at-a-glance)),
with the remainder targeted for a later release. It:

- Summarizes the pre-CSL identity architecture across Camunda platform components (OC Identity, Management Identity, SaaS Auth0) as background.
- Describes a single identity plane, implemented as a hexagonal library embedded in Hub, Optimize, and Orchestration Clusters — see [§2.1](./02-current-state.md#21-rollout-status-at-a-glance) for what of it has shipped versus what remains target design.
- Shows how the architecture supports multiple Physical Tenants per broker/cluster and multi-tenancy.
- Emphasizes that standalone Orchestration Cluster (without Hub) remains a first-class deployment option.
- Outlines how a single shared frontend and pluggable backends (persistence, OC command creation, etc.) fit into the design.
- Keeps SCIM out of this draft intentionally to focus early feedback; SCIM is planned as another inbound port/adapter on top of the same library.

### 1.1 Terminology

Full term definitions are in the [Glossary (§12)](./12-glossary.md). Quick reference for reading the diagrams:

- **Physical Tenant** = an Engine (one execution context inside a Broker). Each Engine is a Physical Tenant. A Broker hosting multiple Engines hosts multiple Physical Tenants.
- **Tenant** = a logical Tenant (data/access partition, e.g. `default`, `retail`) unless written as **Physical Tenant**.
- **OC** at high level = the logical Orchestration Cluster; at runtime = Gateway/Search layer + Broker/Engine layer.
- **Hub UI** / **OC UI** = aggregated management-plane / execution-plane frontends, not per-component UIs.
- **scope** (filter-chain SPI): In the filter-chain SPI, _scope_ refers to a path-isolated API surface with its own security-chain configuration and provider set (see `CamundaSecurityScopeProvider`, ADR-0013).
- **Policy receiver** — a CSL-embedded host application that receives and enforces policy published by Hub, rather than authoring policy locally. OC instances using the `managed` deployment strategy and Optimize in full-mode deployments are policy receivers. See [Glossary (§12)](./12-glossary.md) for the full definition.

---

