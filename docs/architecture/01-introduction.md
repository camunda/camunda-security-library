# Unified Identity Architecture

**IMPORTANT**: This document is a work in progress and reflects the current thinking on the unified identity architecture for Camunda Hub and Orchestration Clusters. It is intended to provide a high-level overview of the proposed design, including key components, interactions, and deployment models.
SCIM provisioning is part of the planned end-state target architecture, but it is intentionally out of scope in this document to get early feedback on the core model first; from the library perspective, SCIM is handled as an additional inbound port/adapter.
The architecture is subject to change as we iterate on the design and gather feedback from stakeholders.

---

## 1. Introduction and goals

This document describes the planned Unified Identity Architecture for Camunda Hub and Orchestration Clusters in an arc42-style structure. It:

- Summarizes the current identity architecture across Camunda platform components (OC Identity, Management Identity, SaaS Auth0).
- Proposes a target architecture with a single identity plane, implemented as a hexagonal library reused in Hub and Orchestration Clusters.
- Shows how the architecture supports multiple Physical Tenants per broker/cluster and multi-tenancy.
- Emphasizes that standalone Orchestration Cluster (without Hub) remains a first-class deployment option.
- Outlines how a single shared frontend and pluggable backends (persistence, OC command creation, etc.) fit into the design.
- Keeps SCIM out of this draft intentionally to focus early feedback; SCIM is planned as another inbound port/adapter on top of the same library.

IMPORTANT: This document shows the final architecture, we won't be able to implement it by October.
We need to break the project down into several iterations with interim goals until we actually reach the endgame.

### 1.1 Terminology

This section defines the terms used throughout the document so diagrams and runtime descriptions can be read consistently.

#### 1.1.1 Orchestration Cluster (OC): logical vs physical view

The term **Orchestration Cluster (OC)** is used at two abstraction levels:

- **Logical view (architecture level):**
  - The OC is the logical execution unit owned by one organization and associated with one policy boundary.
  - High-level diagrams show this as one OC box contrasted with Hub.
- **Physical/deployment view (runtime level):**
  - An OC deployment consists of one or more **Gateways** (the Gateway/Search layer) and one or more **Brokers**.
  - Each Broker contains one or more **Engines**.
  - The Camunda Security Library (CSL) is embedded in the Gateway/Search layer and enforces authentication and authorization before broker/search access.

In high-level diagrams, OC is intentionally simplified as one logical component. In detailed building-block and deployment diagrams (section 5.1 and below), Gateway/Search and Broker/Engine layers are shown explicitly.

#### 1.1.2 Tenant naming and scope rules

- What older drafts called **multi-engine support** is now **Physical Tenant support**.
- In identity-model terms, an **Engine** is a **Physical Tenant**.
- In this document, **Tenant** means **logical Tenant** unless explicitly written as **Physical Tenant**.
- One Physical Tenant can host multiple logical Tenants.
- Multiple Brokers, or multiple Engines within a Broker, create multiple Physical Tenants in one OC.
- In the policy model, `scope_type = PHYSICAL_TENANT` refers to Physical Tenant scope.

#### 1.1.3 Hub UI and OC UI

The terms **Hub UI** and **OC UI** refer to aggregated frontend applications, not separate per-component UIs.

- **Hub UI** (management plane)
  - A single management-plane frontend that consolidates Console, Web Modeler, Admin, and related management capabilities.
  - Hub-side components authenticate and authorize through one CSL instance.
- **OC UI** (execution plane)
  - A single execution-plane frontend that consolidates Operate, Tasklist, and cluster administration capabilities.
  - OC-side components authenticate and authorize through one CSL instance.
  - In full mode (Hub + OC), the admin section is read-only and reflects policy projected from Hub.
  - In OC-only mode, the admin section is read-write and supports local policy authoring.

Both UIs follow the same identity and multi-tenancy model provided by the CSL.

---

