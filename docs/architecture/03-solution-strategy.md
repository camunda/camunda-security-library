## 3. Solution strategy: unified identity plane and library

The target architecture introduces one consistent identity and policy model shared between Hub and all Orchestration Clusters:

- Hub Identity & Policy
  - Source of Truth (SoT) for users, groups, roles, tenants, mapping rules, and authorizations for all clusters and Hub apps.
- OC Identity
  - Per-cluster projection and enforcement of that policy, optimized for runtime access checks, and aware of multiple engines/tenants per cluster.
- Single identity plane for all consumers
  - Web UIs, user apps, workers and integrations are all just API clients authenticated by the Enterprise IdP and authorized against the policy model.

Technically, this is implemented as a pluggable identity/security library:

- Embedded into Hub and Orchestration Cluster.
- Exposes Authentication (OIDC/SAML) and Authorization (RBAC/ABAC) capabilities via well-defined SPIs.
- Reuses the host application’s existing storage and infrastructure via SPI interfaces (no new standalone database or service).

Key design principles (selected):

- One identity plane for Hub and OC, with Hub as policy SoT whenever present.
- One Hub runtime in SaaS, serving many organizations, with organization-aware policy partitioning in shared Hub storage.
- SaaS / self-managed parity: same concepts (tenants, mapping rules, fine‑grained permissions, BYO IdP) in both deployment models.
- Generic library with no product-specific code: the library contains no knowledge of how clusters are discovered or provisioned in any particular host application. All cluster lifecycle interactions go through two dedicated port interfaces — `ClusterRegistrationService` (inbound: host notifies library of new or updated clusters) and `ClusterRegistryPort` (outbound: library queries host for the current cluster list). How a host application (Hub in SaaS, Hub in Self-Managed full mode) learns about new OCs is exclusively an adapter concern and never leaks into the library domain.
- Hexagonal architecture: all persistence, messaging, OC command creation, and engine‑level wiring are behind interfaces; default implementations can be swapped or replaced entirely.
- IdP-agnostic: only relies on OIDC and SAML standards, so any compliant IdP can integrate.
- Automated lifecycle and migrations: IdP claim mapping and policy replication, with idempotent and observable migrations.
- Standalone OC support: OC can act as the top-level policy authority when Hub is absent, mirroring the fallback topologies in existing docs.

### 3.1 Functional user journeys

The following user journeys describe, from a functional perspective, which actors perform which actions in which subsystem. They are not sequence diagrams, but concrete scenarios tying together Hub, Orchestration Clusters, and IdPs.

#### 3.1.1 Configure cluster policies in full mode (Hub + OC)

Short- to midterm target: Admins configure cluster policies (including Physical Tenant-scoped (`PHYSICAL_TENANT`) and Tenant-scoped permissions) primarily in Hub. The admin section of the OC UI exposes a read-only view of the applied policy for that cluster.

- Actor: Organization / platform administrator (Hub)
- Goal: Adjust who can do what on a given Orchestration Cluster and its engines/tenants.
- Main steps:
  1. Admin signs into the Hub UI.
  2. Admin selects a specific Orchestration Cluster and opens its policy configuration.
  3. Admin edits tenants, roles, groups, mapping rules, and authorizations for that cluster, including:
  - Cluster-wide permissions (for example cluster admins).
  - Tenant-scoped permissions (for example `retail` vs `wholesale`).
  - Physical Tenant-scoped (`PHYSICAL_TENANT`).
  4. Hub Camunda Security Library validates and persists the changes in the selected organization scope, producing a new `PolicyVersion` for the target cluster.
  5. Hub propagates the updated policy to the target OC through a platform-owned transport channel; OC Camunda Security Library applies it and updates the Physical Tenant-scoped (`PHYSICAL_TENANT`) projections.
  6. The admin section of the OC UI, in read-only mode, allows cluster operators to view the effective policies per engine and tenant, including the applied policy version.

Outcome: Cluster policies, including Physical Tenant- and Tenant-specific permissions, are authored once in Hub and enforced consistently in the target OC. Cluster operators can inspect, but not change, these policies via the admin section of the OC UI.

#### 3.1.2 Application developer configures a worker client

- Actor: Application developer / project owner
- Goal: Set up a job worker or integration that can safely access cluster APIs.
- Main steps:
  1. Developer creates a machine principal (client) in the UI (Hub UI in full mode, OC UI in OC-only mode), getting client ID and secret or another credential form.
  2. Admin associates the client with one or more tenants and assigns roles or groups appropriate for the worker.
  3. Admin configures mapping rules (if needed) so that the client’s token claims map to the desired roles and tenants.
  4. Developer configures the worker application to request tokens from the Enterprise IdP using the client credentials.
  5. At runtime, the worker calls the OC APIs with those tokens; OC’s Camunda Security Library validates the token against the IdP, derives permissions from the policy model, and enforces them for each request.

Outcome: The worker runs with the minimum required permissions derived from the unified policy model; there is no ad-hoc, engine-specific authorization logic.

#### 3.1.3 End user works across Hub and OC applications

- Actor: End user (for example, modeler, operator, support agent)
- Goal: Use the Hub UI and OC UI with consistent permissions.
- Main steps:
  1. User signs into the Hub UI via the Enterprise IdP.
  2. Hub Camunda Security Library validates the token and derives roles, groups, and tenants from mapping rules.
  3. User creates or edits models, deploys them to a target Orchestration Cluster or environment.
  4. When the user opens the OC UI for that cluster, they authenticate via the same Enterprise IdP; OC’s Camunda Security Library derives the same or related roles/tenants from the token.
  5. In the OC UI, the user can only see and act on data allowed by their tenant- and role-based authorizations (for example, only instances in `retail` tenant, only tasks assigned to their team).

Outcome: The user experiences a consistent identity across Hub and OC: one Enterprise IdP login, one conceptual set of roles and tenants, and predictable access in both management and execution plane UIs.

#### 3.1.4 Configure policies in an OC-only deployment (long-term target)

Long-term target: Bring the same policy model, including Physical Tenant- and Tenant-scoped authorizations, to OC-only deployments. Today OC-only already supports identity and authorizations, but this journey describes the target behavior.

- Actor: Cluster administrator (OC-only)
- Goal: Configure identity and policies for a standalone OC without Hub, including Physical Tenant- and Tenant-scoped rules.
- Main steps:
  1. Cluster admin opens the admin section of the OC UI.
  2. Cluster admin configures the Enterprise IdP connection directly on the OC (OIDC/SAML client settings for the deployment).
  3. Cluster admin creates tenants, roles, groups, and mapping rules in the admin section of the OC UI.
  4. Cluster admin defines authorizations for cluster resources (definitions, instances, tasks, cluster APIs) and, if needed, Physical Tenant- and Tenant-specific scopes.
  5. OC Camunda Security Library persists the policy locally and propagates Physical Tenant-scoped (`PHYSICAL_TENANT`) projections to the engines.

Outcome: The OC acts as local SoT for identity and policy. Users and workers can authenticate via the Enterprise IdP, and permissions are enforced consistently across the OC UI and APIs within that cluster, including Physical Tenant- and Tenant-specific rules.

#### 3.1.5 Configure identity for a new organization (full mode: Hub + OC, long-term target)

Long-term target: Org-level IdP setup and cluster provisioning are performed centrally via Hub.

- Actor: Organization administrator (Hub)
- Goal: Connect the organization’s IdP, provision an Orchestration Cluster, and define baseline access.
- Main steps:
  1. Org admin signs into the Hub UI.
  2. Org admin configures the Enterprise IdP connection for the organization (for example Entra, Okta, Keycloak) via Hub (org-level IdP setup in the target state).
  3. Org admin creates or imports tenants (for example `default`, `retail`, `wholesale`) in the Hub UI.
  4. Org admin defines mapping rules (claims → roles/tenants) and assigns baseline roles and groups for key personas (for example Cluster Admins, Developers, Support).
  5. Org admin provisions (or selects) an Orchestration Cluster and associates it with the organization/tenants.
    - Cluster selection is resolved via the `ClusterRegistryPort`; the host application (Hub) provides the adapter implementation that enumerates available clusters.
  6. Hub Camunda Security Library persists this configuration in the organization-scoped Hub partition, produces a new `PolicyVersion`, and starts propagation to the relevant OC(s).

Outcome: The organization’s IdP is connected, tenants and roles exist, and cluster-local policy is projected to the associated OCs. Cluster admins and developers can authenticate via the Enterprise IdP and start using cluster UIs and APIs, with Hub acting as the central identity and policy entry point.

### 3.2 Quality goals

The Camunda Security Library and unified identity plane must meet the following quality goals:

- Security and correctness
  - Authorization decisions are deterministic: given the same token, policy, and resource, all instances (Hub, OC) reach the same result.
  - Default behavior is deny-by-default if policy, tenant context, or token validation is unclear.
  - All external integrations (IdPs, engines) are accessed via well-defined ports with strict input validation.

- Robustness and resilience
  - Temporary failures (network, IdP, OC downtime) do not corrupt policy state; propagation is retried and gaps can be detected and repaired.
  - Idempotent apply semantics ensure that replays of the same policy version do not change effective behavior.

- Performance and scalability
  - Policy evaluation adds minimal per-request overhead for common paths (UI/API calls, worker calls).
  - Policy propagation is efficient for large numbers of clusters and tenants; in the proposed first iteration, Hub would send full policy payloads and rely on batching/backpressure to keep throughput stable.

- Observability and logging
  - All authentication and authorization decisions are logged with enough context (principal, resource, action, tenant, result, correlation IDs) to trace end-to-end flows.
  - Policy propagation (Hub → OC → Engine) is observable per cluster with clear status (last version applied, last error, latency) and logs for both success and failure paths.
  - Logs follow consistent structure and severity levels so they can be indexed and correlated across Hub and OCs.

- Operational simplicity
  - Identity deployments (Hub, OC-only) are manageable by platform teams without deep knowledge of internal policy data structures.
  - Rollout state of policy per cluster/OC is visible in tooling without digging into raw logs or databases.

---

