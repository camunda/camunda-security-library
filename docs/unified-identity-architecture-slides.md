# Unified Identity Architecture for Camunda Hub &amp; Orchestration Clusters
Patrick Wunderlich – Identity Architecture

---

## 1. Current identity architecture (SaaS &amp; Self-Managed)

- Identity is split across management-plane and execution-plane runtimes.
- SaaS and Self-Managed differ in integration stack and operational model.
- Authentication patterns are not uniform across management-plane components.
- Runtime authorization is primarily enforced through OC Identity in each cluster.

### SaaS today

```mermaid
flowchart TB
  subgraph SaaS_Mgmt["Management plane"]
    ConsoleHub["Console"]
    WebModeler["Web Modeler"]
    Optimize["Optimize"] --> ManagementId["Management Identity"]
  end
  subgraph Execution["Execution plane"]
    Operate["Operate"]
    Tasklist["Tasklist"]
    Identity["Identity / Admin"]
    subgraph OC["Orchestration Cluster"]
      OCId["OC Identity</br>(embedded)"]
    end
  end
  subgraph Customer["Customer landscape"]
    CustIdP["Enterprise IdP</br>(customer-managed)"]
  end
  SaaSAuth0["Auth0 tenant</br>(Camunda-managed, SaaS)"]
  ManagementIdDBUse[("Management Identity DB)")]

  ConsoleHub & WebModeler --> SaaSAuth0
  Operate & Tasklist & Identity --> OC
  OCId --> SaaSAuth0
  SaaSAuth0 --> CustIdP
  ManagementId --> ManagementIdDBUse
```

### Self-Managed today

```mermaid
flowchart TB
  subgraph Mgmt["Management plane"]
    Console["Console"]
    WebModeler["Web Modeler"]
    Optimize["Optimize"]
    MgmtId["Management Identity"]
  end
  subgraph Execution["Execution plane"]
    Operate["Operate"]
    Tasklist["Tasklist"]
    Identity["Identity"]
    subgraph OC["Orchestration Cluster"]
      OCId["OC Identity</br>(embedded)"]
    end
  end
  subgraph Customer["Customer landscape"]
    CustIdP["Enterprise IdP</br>(customer-managed)"]
  end

  Console & WebModeler & Optimize --> MgmtId
  MgmtId --> CustIdP

  Operate & Tasklist & Identity --> OC
  OC --> CustIdP
```

---

## 2. Why we want a new architecture

- Split identity (Management Identity vs OC Identity, plus Auth0)
- Different models and capabilities between SaaS and Self-Managed
- Multiple, inconsistent auth flows on the management plane
- Hard to reason about policy and to achieve parity at scale
- Manual lifecycle/configuration steps (tenants, roles, mappings) remain too high
- Migration/rollout and observability are weaker than required at scale

---

## 3. Solution strategy – unified identity plane

- One consistent identity &amp; policy model shared by Hub and all OCs
- Security Gateway Framework (SGF) as shared hexagonal library
  - Adapter-driven integration keeps domain logic independent from host infrastructure
- Hub as policy SoT when present; OC-only as first-class mode
- AuthN/AuthZ enforcement always active in all runtime profiles
- Same core semantics across Hub and OC reduce behavior drift

---

## 4. Target system context (Full mode &amp; OC-only)

- In both modes, engines do not integrate with IdPs directly.
- Existing infra (IdPs, DBs) is reused; no extra standalone identity service.

### Full mode (Hub + OC)

- Hub authors and distributes policy; OC enforces projected policy.
- Engines do not integrate with IdPs directly.
- Existing infra (IdPs, DBs) is reused; no extra standalone identity service.

```mermaid
flowchart TB
  subgraph Mgmt["Management plane"]
    HubUi["Hub UI (Console, Web Modeler, Admin)"]
    Hub["Hub"]
    HubUi --> Hub
    Optimize["Optimize"]
  end
  subgraph Execution["Execution plane"]
    OcUi["OC UI (Operate, Tasklist, Admin (view only)"]
    OC["Orchestration Cluster"]
    OcUi --> OC
  end
  Infra["Infrastructure (IDPs, DBs)"]

  Hub -->|"policy propagation"| OC
  OC --> Infra
  Hub --> Infra
```

### OC-only mode

- OC-only mode: OC is local policy SoT and enables admin read/write.
- Engines do not integrate with IdPs directly.
- Existing infra (IdPs, DBs) is reused; no extra standalone identity service.

```mermaid
flowchart TB
  subgraph Execution["Execution plane"]
    OcUi["OC UI (Operate, Tasklist, Admin"]
    OC["Orchestration Cluster"]
    OcUi --> OC
  end
  IdPs[("[1 - N] IDPs (per logical tenant/Physical Tenant)")]
  DBs[("DBs (primary/secondary)")]

  OC --> DBs
  OC --> IdPs
```

---

## 5. Building block view – high level

- Hub and OC embed the same SGF core, configured per runtime profile.
- OC uses Security Engine Framework for command-time enforcement in engines.
- Propagation chain is Hub -> OC -> Engine (full mode) or OC -> Engine (standalone).
- Policy scoping supports cluster-wide, logical-tenant, and physical-tenant use cases.

### Full mode – simple (Hub + OC with one engine)

```mermaid
flowchart TB
  subgraph Mgmt["Management plane"]
    HubUi["Hub UI (Console, Web Modeler, Admin)"]
    subgraph Hub["Hub"]
      SecGatHub["Security Gateway Framework"]
    end
    HubUi --> Hub
  end

  subgraph Execution["Execution plane"]
    OcUi["OC UI (Operate, Tasklist, Admin (view only)"]
    subgraph OC["Orchestration Cluster"]
      subgraph GatewayLayer["Gateway / Search Layer"]
        SecGatOC["Security Gateway Framework</br>(embedded in Gateway)"]
      end
      subgraph Broker["Broker"]
        Engine["Engine</br>(Physical Tenant)"]
        SecEngFrame["Security Engine Framework"]
      end
      SecGatOC -->|"config propagation</br>(batch operation)"| Broker
    end
    OcUi --> GatewayLayer
  end

  IdPs[("[1 - N] IDPs (per logical tenant/Physical Tenant)")]
  DBs[("DBs (primary/secondary)")]
  HubDb[("Hub DB")]

  SecGatHub -->|"config propagation"| SecGatOC
  Broker --> DBs
  OC & Hub --> IdPs
  Hub --> HubDb

  style Broker fill:#34a853,color:#fff
```

### OC-only mode – simple (standalone OC with one engine)

```mermaid
flowchart TB
  subgraph Execution["Execution plane"]
    OcUi["OC UI (Operate, Tasklist, Admin"]
    subgraph OC["Orchestration Cluster"]
      subgraph GatewayLayer["Gateway / Search Layer"]
        OCLib["Security Gateway Framework"]
      end
      subgraph Broker["Broker"]
        Engine["Engine</br>(Physical Tenant)"]
        EngLib["Security Engine Framework"]
      end
      OCLib -->|"config propagation</br>(batch operation)"| Broker
    end
  end

  OcUi --> GatewayLayer

  IdPs[("[1 - N] IDPs (per logical tenant/Physical Tenant)")]
  DBs[("DBs (primary/secondary)")]

  Broker --> DBs
  OC --> IdPs

  style Broker fill:#34a853,color:#fff
```

---

## 6. Unified policy model

- Organization (Hub partition, esp. SaaS)
- Tenant (logical)
- Group and Role
- MappingRule
- Principal (user/machine)
- Authorization (owner → resource → permissions, with ALL / TENANT / PHYSICAL_TENANT scopes)
- Same model is used for Hub authoring and OC/engine enforcement
- Mapping rules bridge IdP claims to platform permissions
- Supports human users and machine principals consistently

---

## 7. Outbox-based policy propagation (Hub → OCs)

- Hub writes `PolicyVersion` and `OutboxEvent` in one transaction.
- OCs apply snapshots idempotently and track `last_applied_version`.
- Hub tracks per-OC ack state (`OcSyncState`) for rollout visibility.
- Delivery is at-least-once; retries are explicit and observable.
- OC applies payloads via batch operations to engines (per Physical Tenant).
- Engine applies identity policy to primary storage; exporters project it to OC secondary storage.

### High-level flow

```mermaid
flowchart TB
  subgraph Hub["Hub"]
    subgraph subHubLib["Security Gateway Framework</br>(Hub instance)"]
      Dispatcher["Outbox Dispatcher"]
    end
  end
  HubDB[("Hub DB")]

  subgraph OC1["Orchestration Cluster A"]
    OC1Lib["Security Gateway Framework A</br>(OC instance)"]
    Engine1["Engine"]
  end
  OC1DB[("OC1 DB (Primary / Secondary)")]

  subgraph OC2["Orchestration Cluster B"]
    OC2Lib["Security Gateway Framework B</br>(OC instance)"]
    Engine2["Engine"]
  end
  OC2DB[("OC2 DB (Primary / Secondary)")]

  Hub --> HubDB
  OC1 --> OC1DB
  OC2 --> OC2DB

  Dispatcher -->|"POST POLICY_SNAPSHOT (full policy)</br>/identity/policies/apply"| OC1Lib & OC2Lib

  OC1Lib -->|"Apply full policy snapshot</br>to local projection"| Engine1
  OC2Lib -->|"Apply full policy snapshot</br>to local projection"| Engine2
```

### Detailed outbox flow

```mermaid
flowchart TB
  subgraph HUB["Hub scope"]
    direction TB
    HubUi["Hub UI (Console, Web Modeler, Admin) / API"] --> HubSvc["Hub Security Gateway Framework"]

    subgraph HubTx["Hub transaction"]
      direction TB
      HubSvc --> WritePolicy["Write PolicyVersion"]
      HubSvc --> WriteOutbox["Write OutboxEvent</br>status=PENDING"]
    end

    WritePolicy & WriteOutbox --> Commit["Commit TX"]

    Commit --> Poll["Outbox Dispatcher polls</br>PENDING events"]
    Poll --> Snapshot["Build POLICY_SNAPSHOT"]
    Snapshot --> Send["POST /identity/policies/apply"]
    Ack["(Response from OC) ACK with last_applied_version"] --> Delivered["Mark OutboxEvent DELIVERED"]
    Failed["(Response from OC) Mark OutboxEvent FAILED</br>attempts++ / next_attempt_at"] --> Poll
  end

  subgraph OC_SCOPE["OC scope"]
    direction TB
    OCApply["Security Gateway Framework validates and applies payload"]
    BatchOps["Create batch operations</br>per Physical Tenant"]
    EnginePrimary["Engine (SEF) applies identity policy</br>to primary storage"]
    Exporter["Exporter projects identity policy</br>to OC secondary storage tables"]
    OCApply --> BatchOps
    BatchOps --> EnginePrimary
    EnginePrimary --> Exporter
  end

  Send --> OCApply
  Exporter --> Ack
```

---

## 8. Policy data model

Minimal conceptual schema:

```text
OcSyncState
  organization_id    -- organization boundary in Hub
  oc_id              -- stable identifier of the target OC
  cluster_id
  last_acked_version -- last PolicyVersion successfully delivered and ACKed
  last_sync_at

OutboxEvent
  id
  organization_id
  oc_id              -- target OC for this delivery attempt
  policy_version_id
  event_type         -- POLICY_SNAPSHOT (iteration one; extensible)
  status             -- 'PENDING' | 'DELIVERED' | 'FAILED'
  attempts
  next_attempt_at

PolicyVersion
  id
  organization_id
  cluster_id
  version_number
  base_version       -- optional; reserved for possible future diff-based propagation

EntityRevision
  id
  organization_id
  entity_type
  entity_id
  introduced_in_policy_version
  scope_type
  scope_id
  is_deleted
  payload            -- single referenced entity JSON
```

- `OutboxEvent`
  - One row per policy delivery attempt to a specific cluster.
  - In shared-Hub deployments, includes the organization boundary and concrete target OC to make routing and operations explicit.
  - `event_type` is `POLICY_SNAPSHOT`.
  - Drives asynchronous delivery and retry without coupling Hub writes to OC availability.
- `OcSyncState`
  - One row per target OC.
  - Scoped by organization in shared-Hub deployments.
  - Tracks `last_acked_version`: the last `PolicyVersion` successfully delivered and acknowledged.
  - Read by the Outbox Dispatcher to track delivery progress and retries per OC.
- `PolicyVersion`
  - One row per cluster and version of the desired policy.
  - Represents the canonical policy commit for a cluster within one organization boundary.
- `EntityRevision`
  - Immutable revision payload per changed entity.
  - Stores one referenced entity JSON payload per row or delete tombstones (`is_deleted`).
  - Used to reconstruct snapshots (latest non-deleted revision per entity/scope up to target version).
  - Practical persistence split:
    - Keep canonical current-state tables per entity (role/group/authorization/etc.) for normal queries and constraints.
    - Keep `EntityRevision.payload` as JSON for versioned transport, idempotent apply, and snapshot/diff reconstruction.
    - Do not require fully normalized historical tables per version.

---

## 9. Security Gateway Framework

- Inbound and outbound ports are defined in the library core.
- Host applications provide adapters; core stays infrastructure-agnostic.
- The same port model is used in Hub and OC runtimes.
- Swapping persistence/IdP/dispatch adapters does not change domain logic.

This is just an example of the library core! 
We still have to define how we really want to implement it. 

```mermaid
graph LR
  subgraph EXT_IN["Inbound adapters (host application)"]
    AC["Admin REST Controller</br>@RestController, Spring MVC"]
    PEP["PEP / Security Filter</br>Spring Security Filter Chain"]
    PAC["Policy Apply Controller</br>POST /identity/policies/apply"]
    CREG_IN["Cluster Registration Adapter</br>triggered by provisioning events,</br>config, or any host-side mechanism"]
  end

  subgraph CORE["Security Gateway Framework (library)"]
    subgraph IN_PORTS["Inbound port interfaces</br>(defined in Core)"]
      PS["PolicyService"]
      AZ["AuthorizationService"]
      TS["TenantService"]
      PA["PolicyApplyService"]
      CRS["ClusterRegistrationService</br>(HUB only)"]
    end
    DL["Domain Logic</br>(implements inbound ports,</br>calls outbound ports)"]
    subgraph OUT_PORTS["Outbound port interfaces</br>(defined in Core)"]
      PR["PolicyRepository"]
      OX["OutboxPort"]
      IDP_P["IdpPort"]
      CMD_P["EngineCommandPort</br>(OC runtime only)"]
      FT_P["FeatureTogglePort"]
      CRX["ClusterRegistryPort</br>(HUB only)"]
    end
  end

  subgraph EXT_OUT["Outbound adapter implementations (host application or default modules)"]
    PR_I["PolicyRepository</br>Hub: Spring Data JPA</br>OC: RDBMS / ES adapter"]
    OX_I["OutboxPort</br>SQL transactional outbox</br>(same TX as business change)"]
    IDP_I["IdpPort</br>OIDC/SAML client</br>(Keycloak, Entra, Auth0)"]
    CMD_I["EngineCommandPort</br>Engine projection command adapter</br>(OC backend service layer)"]
    FT_I["FeatureTogglePort</br>Spring @ConfigurationProperties</br>or Unleash / LaunchDarkly"]
    CRX_I["ClusterRegistryPort</br>Hub adapter: in-memory registry</br>populated via ClusterRegistrationService"]
  end

  AC -->|"calls"| PS
  PEP -->|"calls"| AZ
  PAC -->|"calls"| PA
  CREG_IN -->|"calls"| CRS

  PS & AZ & TS & PA & CRS -->|"implemented by"| DL

  DL -->|"calls"| PR & OX & IDP_P & CMD_P & FT_P & CRX

  PR -->|"implemented by"| PR_I
  OX -->|"implemented by"| OX_I
  IDP_P -->|"implemented by"| IDP_I
  CMD_P -->|"implemented by"| CMD_I
  FT_P -->|"implemented by"| FT_I
  CRX -->|"implemented by"| CRX_I
```

---

## 10. Runtime profiles and mode switching

- Profile selects capabilities; AuthN/AuthZ remains always on.
- `HUB` enables policy authoring, versioning, outbox, and cluster registration.
- `OC_MANAGED` enables remote apply + engine projection (admin read-only).
- `OC_STANDALONE` enables local authoring + engine projection (admin read/write).
- All profiles reuse the same shared core and policy semantics.

```mermaid
flowchart TB
  Start["Library bootstrap"] --> Profile{"runtime.profile"}

  Profile -->|"HUB"| Hub["Enable Hub services<br>AuthN/AuthZ (Hub-scoped)<br>PolicyAuthoring + Versioning + OutboxDispatch"]
  Profile -->|"OC_MANAGED"| OCM["Enable OC managed services<br>AuthN/AuthZ (cluster-scoped)<br>RemotePolicyApply + ProjectionToEngine"]
  Profile -->|"OC_STANDALONE"| OCS["Enable OC standalone services<br>AuthN/AuthZ (cluster-scoped)<br>LocalPolicyAuthoring + ProjectionToEngine"]

  Core["Always-on core<br>Spring Security filter chain<br>Scope resolver + Session handling<br>IdpPort (all modes)"]

  Hub --> HubIn["Inbound ports enabled:<br>AuthorizationService, TenantService, PolicyService,<br>ClusterRegistrationService"]
  OCM --> OCMIn["Inbound ports enabled:<br>AuthorizationService, TenantService, PolicyApplyService"]
  OCS --> OCSPin["Inbound ports enabled:<br>AuthorizationService, TenantService, PolicyService"]

  Hub --> HubPorts["Outbound ports required:<br>PolicyRepository, IdpPort, OutboxPort,<br>SessionStore, ClusterRegistryPort"]
  OCM --> OCMPorts["Outbound ports required:<br>PolicyRepository, IdpPort, EngineCommandPort, SessionStore"]
  OCS --> OCSPorts["Outbound ports required:<br>PolicyRepository, IdpPort, EngineCommandPort, SessionStore"]
```

### 10.1 Shared components

```mermaid
flowchart LR
  subgraph SharedCore["Shared library core (all modes)"]
    SpringSec["Spring Security<br>filter chain configuration"]
    AuthN["AuthN pipeline<br>(IdpPort → token validation<br>+ session management)"]
    AuthZ["AuthZ evaluator<br>(scope-aware RBAC/ABAC<br>for Hub or cluster resources)"]
    Domain["Unified policy domain<br>(Tenant/Role/Group/MappingRule/Principal/Authz)"]
    Apply["Policy apply engine<br>(full snapshot in iteration one;<br>idempotent, version-checked)"]

    SpringSec --> AuthN
  end

  subgraph HubRuntime["HUB runtime only"]
    HubAuthoring["Policy authoring<br>(Hub-scoped: org/workspace/cluster)"]
    HubOutbox["Outbox dispatcher<br>(PolicyVersion + OutboxPort)"]
    HubCluster["Cluster registry<br>(ClusterRegistrationService ← host<br>ClusterRegistryPort → host adapter)"]
    HubAuthoring --> HubOutbox
  end

  subgraph OcRuntime["OC runtime (managed + standalone)"]
    OcWrite["Policy apply or local write"]
    OcProject["Engine projection<br>(EngineCommandPort)"]
    OcWrite --> OcProject
  end

  Domain --> HubAuthoring
  Apply --> OcWrite
```

---

## 11. Security Engine Framework

- Engine-side counterpart to SGF, embedded in Zeebe engine runtime.
- Receives identity commands from OC via `EngineCommandPort` mapping.
- Performs command-time authorization using local projected identity state.
- Keeps engine independent from direct IdP integration.

```mermaid
graph LR
  subgraph EXT_IN_SEF["Inbound adapters (engine)"]
    CMD_IN["Identity Command Handler</br>receives commands from OC via EngineCommandPort"]
    AUTHZ_IN["Authorization Request Handler</br>called by engine command processing"]
  end

  subgraph SEF["Security Engine Framework (embedded in engine)"]
    subgraph IN_PORTS_SEF["Inbound port interfaces"]
      ICP["IdentityCommandPort</br>(apply policy updates to engine state)"]
      EAP["EngineAuthorizationPort</br>(evaluate authz for engine operations)"]
    end
    SEF_LOGIC["Domain Logic</br>(applies identity state,</br>evaluates RBAC/ABAC per command)"]
    subgraph OUT_PORTS_SEF["Outbound port interfaces"]
      ISP["IdentityStatePort</br>(read / write identity state)"]
    end
  end

  subgraph EXT_OUT_SEF["Outbound adapter implementations"]
    ROCKS["IdentityStatePort</br>RocksDB (primary storage)</br>AuthorizationState, MembershipState,</br>MappingRuleState, TenantState"]
  end

  CMD_IN -->|"calls"| ICP
  AUTHZ_IN -->|"calls"| EAP
  ICP & EAP -->|"implemented by"| SEF_LOGIC
  SEF_LOGIC -->|"calls"| ISP
  ISP -->|"implemented by"| ROCKS
```

---

## 12. Config propagation to the engine via batch operations
- Use existing Batch Operation feature per Physical Tenant
- Single batch per engine per policy update
- Atomicity, scalability, observability via batch infrastructure
- Reuses existing engine infrastructure; no bespoke bulk command channel
- Fits OC-to-engine projection model and failure-handling semantics

---

## 13. Frontend integration

- Identity Admin UI as versioned npm package
- Consumed by Hub UI and OC UI
- Narrow, explicit contracts; React-based composition
- Host applications provide auth/routing/theme/i18n/telemetry context
- Keep fallback option: thin web-component wrapper only if needed
- Goal: minimize app-specific glue code and cross-app UX drift

---

## 14. Runtime view – admin configures cluster policies in full mode

- Admin authors policy centrally in Hub for target clusters.
- Hub validates principal context and persists policy/version/outbox atomically.
- Outbox dispatcher pushes full snapshots to target OCs.
- OC applies snapshots idempotently and propagates engine-scoped changes.
- OC UI admin section shows projected state in read-only mode.

```mermaid
sequenceDiagram
  actor Admin
  box Hub
    participant HubUI as Hub UI (Console, Web Modeler, Admin)
    participant HubSGF as Hub Security Gateway Framework
    participant Outbox as Outbox Dispatcher
  end
  participant IdP as Hub IdP
  participant HubDB as Hub DB
  box Orchestration Cluster
    participant OCSGF as OC Security Gateway Framework
    participant Engine as Engine(s)
  end

  Admin->>HubUI: Log in and manage policies
  HubUI->>HubSGF: Authn/authz request
  HubSGF->>IdP: Validate identity and derive roles/tenants
  IdP-->>HubSGF: Token/claims
  HubUI->>HubSGF: Submit policy updates
  HubSGF->>HubDB: Persist policy + PolicyVersion + revisions + outbox events
  Outbox->>HubDB: Read pending events
  Outbox->>OCSGF: POST /identity/policies/apply (full snapshot)
  OCSGF->>OCSGF: Apply snapshot projection
  OCSGF->>Engine: Propagate engine-scoped changes
```

---

## 15. Deployment view

- Supports Self-Managed OC-only, Self-Managed full mode, and SaaS shared-Hub models.
- Keeps same identity core while varying operational topology.
- Preserves clear SoT boundaries and propagation responsibilities.
- Reuses existing customer/Camunda infrastructure depending on deployment model.


### Self-Managed – full mode (Hub + OC)

```mermaid
flowchart TB
  subgraph Customer["Customer-managed Infrastructure"]
    subgraph MgmtPlane["Management Plane"]
      Console["Console"]
      WebModeler["Web Modeler"]
      AdminHub["Admin UI (read/write)"]
      subgraph Hub["Hub"]
        SecGatHub["Security Gateway Framework"]
      end
      Console & WebModeler & AdminHub --> Hub
    end
    subgraph Execution["Execution Plane"]
      Operate["Operate"]
      Tasklist["Tasklist"]
      AdminOC["Admin UI (view-only)"]
      subgraph OC["Orchestration Cluster"]
        subgraph GatewayLayer["Gateway / Search Layer"]
          SecGatOC["Security Gateway Framework"]
        end
        subgraph Broker1["Broker"]
          SecEngFrame1["Security Engine Framework"]
        end
      end
      Operate & Tasklist & AdminOC --> OC
    end
    HubDB[("Hub DB")]
    OCDB[("OC DB (Primary / Secondary)")]
    Hub --> OC
    Hub --> HubDB
    OC --> OCDB
  end
  EnterpriseIdP[["Enterprise IdP</br>(Keycloak, Entra, Okta, ...)"]]
  Hub & OC --> EnterpriseIdP
```

### Self-Managed – OC-only standalone (2 gateways + 3 brokers)

```mermaid
flowchart TB
  subgraph Customer["Customer-managed Infrastructure"]
    subgraph Execution["Execution Plane"]
      subgraph GW1["Gateway 1"]
        GW1SGF["Security Gateway Framework"]
      end
      subgraph GW2["Gateway 2"]
        GW2SGF["Security Gateway Framework"]
      end
      subgraph Broker1["Broker 1"]
        B1E1["Engine A</br>(Physical Tenant)"]
        B1E2["Engine B</br>(Physical Tenant)"]
        B1SEF["Security Engine Framework"]
      end
      subgraph Broker2["Broker 2"]
        B2E1["Engine C</br>(Physical Tenant)"]
        B2E2["Engine D</br>(Physical Tenant)"]
        B2SEF["Security Engine Framework"]
      end
      subgraph Broker3["Broker 3"]
        B3E1["Engine E</br>(Physical Tenant)"]
        B3E2["Engine F</br>(Physical Tenant)"]
        B3SEF["Security Engine Framework"]
      end
      GW1 --> Broker1
      GW1 --> Broker2
      GW2 --> Broker2
      GW2 --> Broker3
    end
    DBs[("DBs (Primary / Secondary)")]
  end
  EnterpriseIdP[["Enterprise IdP</br>(Keycloak, Entra, Okta, ...)"]]
  Execution --> DBs
  GW1 & GW2 --> EnterpriseIdP
```

### Self-Managed – OC-only mode

```mermaid
flowchart TB
  subgraph Customer["Customer-managed Infrastructure"]
    subgraph Execution["Execution Plane"]
      Operate["Operate"]
      Tasklist["Tasklist"]
      AdminUI["Admin UI (read/write)"]
      subgraph OC["Orchestration Cluster"]
        subgraph GatewayLayer["Gateway / Search Layer"]
          SecGatOC["Security Gateway Framework"]
        end
        subgraph Broker1["Broker"]
          SecEngFrame1["Security Engine Framework"]
        end
      end
      Operate & Tasklist & AdminUI --> GatewayLayer
    end
    DBs[("DBs (Primary / Secondary)")]
    Broker1 --> DBs
  end
  EnterpriseIdP[["Enterprise IdP</br>(Keycloak, Entra, Okta, ...)"]]
  OC --> EnterpriseIdP
```

### SaaS – shared Hub across organizations

```mermaid
flowchart TB
  subgraph Camunda["Camunda-managed infrastructure"]
    subgraph SharedMgmt["Shared management plane"]
      Console["Console"]
      WebModeler["Web Modeler"]
      AdminHub["Admin UI (read/write)"]
      subgraph Hub["Shared Hub"]
        SecGatHub["Security Gateway Framework"]
      end
      Console --> Hub
      WebModeler --> Hub
      AdminHub --> Hub
    end
    subgraph OrgA["Organization A"]
      OCA["Orchestration Cluster A"]
    end
    subgraph OrgB["Organization B"]
      OCB["Orchestration Cluster B"]
    end
    Hub --> OCA
    Hub --> OCB
  end
  EnterpriseIdP[["Enterprise IdPs / brokers</br>(customer-managed or SaaS-managed during migration)"]]
  Hub --> EnterpriseIdP
  OCA --> EnterpriseIdP
  OCB --> EnterpriseIdP
```
