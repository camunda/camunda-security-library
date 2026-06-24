## 1. Introduction and goals

> **Document structure:** Sections 1 and 2 provide as-is context — the current identity architecture and its limitations. The arc42 target architecture begins at section 3.

This document describes the planned Unified Identity Architecture for Camunda Hub and Orchestration Clusters in an arc42-style structure. It:

- Summarizes the current identity architecture across Camunda platform components (OC Identity, Management Identity, SaaS Auth0).
- Proposes a target architecture with a single identity plane, implemented as a hexagonal library reused in Hub and Orchestration Clusters.
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
- **scope** (filter-chain SPI): In the filter-chain SPI, _scope_ refers to a path-isolated API surface with its own security-chain configuration and provider set (see `CamundaSecurityScopeProvider`, ADR-0025).
- **Policy receiver** — a CSL-embedded host application that receives and enforces policy published by Hub, rather than authoring policy locally. OC instances using the `managed` deployment strategy and Optimize in full-mode deployments are policy receivers. See [Glossary (§12)](./12-glossary.md) for the full definition.

---

