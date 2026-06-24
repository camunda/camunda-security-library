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
- Exposes Authentication (OIDC) and Authorization (RBAC/ABAC) capabilities via well-defined extension interfaces.
- Reuses the host application’s existing storage and infrastructure via port interfaces (no new standalone database or service).

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

The supported deployment modes produce three primary actor contexts: policy admins working in Hub (full mode), cluster admins working in OC-only mode, and end users or developers working across both planes.

Detailed illustrative scenarios for each context — including step-by-step walkthroughs of policy authoring, worker client setup, cross-plane user access, and org provisioning — are documented in **[docs/user-journeys.md](../user-journeys.md)**.

### 3.2 Quality goals

The Camunda Security Library and unified identity plane must meet the following quality goals. The order is intentional and reflects priority: a later goal may be traded off against an earlier one if required, but not the reverse.

1. **Security and correctness**
   - Authorization decisions are deterministic: given the same token, policy, and resource, all instances (Hub, OC) reach the same result.
   - Default behavior is deny-by-default if policy, tenant context, or token validation is unclear.
   - All external integrations (IdPs, engines) are accessed via well-defined ports with strict input validation.

2. **Robustness and resilience**
   - Temporary failures (network, IdP, OC downtime) do not corrupt policy state; propagation is retried and gaps can be detected and repaired.
   - Idempotent apply semantics ensure that replays of the same policy version do not change effective behavior.

3. **Performance and scalability**
   - Policy evaluation adds minimal per-request overhead for common paths (UI/API calls, worker calls).
   - Policy propagation is efficient for large numbers of clusters and tenants; in the proposed first iteration, Hub would send full policy payloads and rely on batching/backpressure to keep throughput stable.

4. **Observability and logging**
   - All authentication and authorization decisions are logged with enough context (principal, resource, action, tenant, result, correlation IDs) to trace end-to-end flows.
   - Policy propagation (Hub → OC → Engine) is observable per cluster with clear status (last version applied, last error, latency) and logs for both success and failure paths.
   - Logs follow consistent structure and severity levels so they can be indexed and correlated across Hub and OCs.

5. **Operational simplicity**
   - Identity deployments (Hub, OC-only) are manageable by platform teams without deep knowledge of internal policy data structures.
   - Rollout state of policy per cluster/OC is visible in tooling without digging into raw logs or databases.

---

