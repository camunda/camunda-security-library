## 12. Glossary

Full term definitions for diagrams and runtime descriptions throughout this document.

### Orchestration Cluster (OC): logical vs physical view

The term **Orchestration Cluster (OC)** is used at two abstraction levels:

- **Logical view (architecture level):**
  - The OC is the logical execution unit owned by one organization and associated with one policy boundary.
  - High-level diagrams show this as one OC box contrasted with Hub.
- **Physical/deployment view (runtime level):**
  - An OC deployment consists of one or more **Gateways** (the Gateway/Search layer) and one or more **Brokers**.
  - Each Broker contains one or more **Engines**.
  - The Camunda Security Library (CSL) is embedded in the Gateway/Search layer and enforces authentication and authorization before broker/search access.

In high-level diagrams, OC is intentionally simplified as one logical component. In detailed building-block and deployment diagrams (section 5.1 and below), Gateway/Search and Broker/Engine layers are shown explicitly.

### Tenant naming and scope rules

- What older drafts called **multi-engine support** is now **Physical Tenant support**.
- In identity-model terms, an **Engine** is a **Physical Tenant**. Each Engine is a Physical Tenant. A Broker hosting multiple Engines hosts multiple Physical Tenants; multiple Brokers in one OC multiply the Physical Tenant count.
- In this document, **Tenant** means **logical Tenant** unless explicitly written as **Physical Tenant**.
- One Physical Tenant can host multiple logical Tenants.
- In the policy model, `scope_type = PHYSICAL_TENANT` refers to Physical Tenant scope.

### Hub UI and OC UI

The terms **Hub UI** and **OC UI** refer to aggregated frontend applications, not separate per-component UIs.

- **Hub UI** (management plane): A single management-plane frontend that consolidates Console, Web Modeler, Admin, and related management capabilities. Hub-side components authenticate and authorize through one CSL instance.
- **OC UI** (execution plane): A single execution-plane frontend that consolidates Operate, Tasklist, and cluster administration capabilities. OC-side components authenticate and authorize through one CSL instance. In full mode (Hub + OC), the admin section is read-only and reflects policy projected from Hub. In standalone mode, the admin section is read-write and supports local policy authoring.

### SPI (in CSL context)

An extension interface in `spring-boot-starter/spi/` (or `api/context/`) that host applications implement to customize CSL behaviour — for example providing a custom access-denied handler or contributing scoped security chains. Registered via Spring's `@ConditionalOnMissingBean` bean mechanism. **Not** a Java `java.util.ServiceLoader`-based SPI.

### IdP/broker

In the SaaS legacy context, Auth0 acts as an identity federation layer (broker): it is Camunda-operated, federates customer Enterprise IdPs, and issues tokens to Camunda services. In the target architecture, customers connect their Enterprise IdP directly; no Camunda-operated broker sits between the customer's IdP and CSL.

### Policy receiver

A CSL-embedded host application that receives and enforces policy published by Hub, rather than authoring policy locally. OC instances using the `managed` deployment strategy and Optimize in full-mode deployments are policy receivers.

Policy receivers maintain a local projection of the Hub-authored policy, updated via `POLICY_SNAPSHOT` messages whenever Hub commits a new `PolicyVersion`. They do not own policy authoring, tenant creation, or outbox dispatch — those capabilities are active only in the `hub` deployment strategy. Contrast with:

- **Hub** (`hub` strategy) — the policy source of truth; authors policy and propagates it to policy receivers.
- **OC in `standalone` mode** — its own local policy source of truth; not a policy receiver.

---

### Sources

- [Unified Identity Target Architecture for Camunda Hub and Orchestration Clusters](https://docs.google.com/document/d/1ExLH2KYmz_V7Zq51adzz9c1Yk2s5ZR7ZhhIKwaEcPs0)

