# Functional User Journeys

These journeys are illustrative scenarios, not normative requirements. They show how the unified policy model and Camunda Security Library connect actors to subsystems across the supported deployment modes.

---

## Journey 1: Configure cluster policies in full mode (Hub + OC)

Short- to midterm target: Admins configure cluster policies (including Physical Tenant-level (`PHYSICAL_TENANT`) and Tenant-level permissions) primarily in Hub. The admin section of the OC UI exposes a read-only view of the applied policy for that cluster. **Not yet implemented** — Hub policy authoring on CSL and Hub → OC distribution are both targeted work, see [rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

- Actor: Organization / platform administrator (Hub)
- Goal: Adjust who can do what on a given Orchestration Cluster and its engines/tenants.
- Main steps:
  1. Admin signs into the Hub UI.
  2. Admin selects a specific Orchestration Cluster and opens its policy configuration.
  3. Admin edits tenants, roles, groups, mapping rules, and authorizations for that cluster, including:
     - Cluster-wide permissions (for example cluster admins).
     - Tenant-level permissions (for example `retail` vs `wholesale`).
     - Physical Tenant-level (`PHYSICAL_TENANT`).
  4. Hub Camunda Security Library validates and persists the changes in the selected organization scope, producing a new `PolicyVersion` for the target cluster. (Hub policy authoring on CSL is not yet implemented — today this still runs through Management Identity, see [rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).)
  5. Hub propagates the updated policy to the target OC through a platform-owned transport channel; OC Camunda Security Library applies it and updates the Physical Tenant-level (`PHYSICAL_TENANT`) projections. (This distribution channel is not yet implemented — see the same table.)
  6. The admin section of the OC UI, in read-only mode, allows cluster operators to view the effective policies per engine and tenant, including the applied policy version. (Depends on step 5's distribution channel, so also not yet implemented.)

Outcome: Cluster policies, including Physical Tenant- and Tenant-specific permissions, are authored once in Hub and enforced consistently in the target OC. Cluster operators can inspect, but not change, these policies via the admin section of the OC UI.

---

## Journey 2: Application developer configures a worker client

- Actor: Application developer / project owner
- Goal: Set up a job worker or integration that can safely access cluster APIs.
- Main steps:
  1. Developer creates a machine principal (client) in the UI (Hub UI in full mode, OC UI in OC-only mode), getting client ID and secret or another credential form.
  2. Admin associates the client with one or more tenants and assigns roles or groups appropriate for the worker.
  3. Admin configures mapping rules (if needed) so that the client's token claims map to the desired roles and tenants.
  4. Developer configures the worker application to request tokens from the Enterprise IdP using the client credentials.
  5. At runtime, the worker calls the OC APIs with those tokens; OC's Camunda Security Library validates the token against the IdP, derives permissions from the policy model, and enforces them for each request — shipped, one evaluator for both the gateway/search layer and the engine, see [ADR-0014](./adr/0014-unified-authz-framework-in-core.md).

Outcome: The worker runs with the minimum required permissions derived from the unified policy model; there is no ad-hoc, engine-specific authorization logic.

---

## Journey 3: End user works across Hub and OC applications

Authentication (steps 1, 4) is shipped for both hosts. Hub's role/tenant derivation for
authorization is still on Management Identity, so the cross-Hub/OC role consistency this journey
describes is the design target, not yet implemented — see
[rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

- Actor: End user (for example, modeler, operator, support agent)
- Goal: Use the Hub UI and OC UI with consistent permissions.
- Main steps:
  1. User signs into the Hub UI via the Enterprise IdP.
  2. Hub Camunda Security Library authenticates the user; role/group/tenant derivation for authorization is still performed by Management Identity today.
  3. User creates or edits models, deploys them to a target Orchestration Cluster or environment.
  4. When the user opens the OC UI for that cluster, they authenticate via the same Enterprise IdP; OC's Camunda Security Library derives roles/tenants from the token and evaluates authorization — shipped for OC (see [ADR-0014](./adr/0014-unified-authz-framework-in-core.md)). Whether these roles/tenants are "the same or related" to Hub's depends on the not-yet-implemented Hub → OC policy distribution.
  5. In the OC UI, the user can only see and act on data allowed by their tenant- and role-based authorizations (for example, only instances in `retail` tenant, only tasks assigned to their team).

Outcome (target): The user experiences a consistent identity across Hub and OC: one Enterprise IdP login, one conceptual set of roles and tenants, and predictable access in both management and execution plane UIs.

---

## Journey 4: Configure policies in an OC-only deployment (long-term target)

Long-term target: Bring the same policy model, including Physical Tenant- and Tenant-level authorizations, to OC-only deployments. Today OC-only already supports authentication and the authorization read/check path on CSL — this journey's authoring steps (3-5) describe the target behavior and are not yet implemented, see [rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

- Actor: Cluster administrator (OC-only)
- Goal: Configure identity and policies for a standalone OC without Hub, including Physical Tenant- and Tenant-level rules.
- Main steps:
  1. Cluster admin opens the admin section of the OC UI.
  2. Cluster admin configures the Enterprise IdP connection directly on the OC (OIDC/SAML client settings for the deployment).
  3. Cluster admin creates tenants, roles, groups, and mapping rules in the admin section of the OC UI. (Authoring UI/path not yet implemented.)
  4. Cluster admin defines authorizations for cluster resources (definitions, instances, tasks, cluster APIs) and, if needed, Physical Tenant- and Tenant-level authorization levels. (Not yet implemented.)
  5. OC Camunda Security Library is designed to persist the policy locally and propagate Physical Tenant-level (`PHYSICAL_TENANT`) projections to the engines via `EngineCommandPort`, which is not yet defined in `core/port/out/` — see [rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

Outcome: The OC acts as local SoT for identity and policy. Users and workers can authenticate via the Enterprise IdP, and permissions are enforced consistently across the OC UI and APIs within that cluster, including Physical Tenant- and Tenant-level rules.

---

## Journey 5: Configure identity for a new organization (full mode: Hub + OC, long-term target)

Long-term target: Org-level IdP setup and cluster provisioning are performed centrally via Hub.

- Actor: Organization administrator (Hub)
- Goal: Connect the organization's IdP, provision an Orchestration Cluster, and define baseline access.
- Main steps:
  1. Org admin signs into the Hub UI.
  2. Org admin configures the Enterprise IdP connection for the organization (for example Entra, Okta, Keycloak) via Hub (org-level IdP setup in the target state).
  3. Org admin creates or imports tenants (for example `default`, `retail`, `wholesale`) in the Hub UI.
  4. Org admin defines mapping rules (claims → roles/tenants) and assigns baseline roles and groups for key personas (for example Cluster Admins, Developers, Support).
  5. Org admin provisions (or selects) an Orchestration Cluster and associates it with the organization/tenants.
    - Cluster selection is resolved via the `ClusterRegistryPort`; the host application (Hub) provides the adapter implementation that enumerates available clusters.
  6. Hub Camunda Security Library is designed to persist this configuration in the organization-scoped Hub partition, produce a new `PolicyVersion`, and start propagation to the relevant OC(s) — not yet implemented, see [rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

Outcome (target): The organization's IdP is connected, tenants and roles exist, and cluster-local policy is projected to the associated OCs. Cluster admins and developers can authenticate via the Enterprise IdP and start using cluster UIs and APIs, with Hub acting as the central identity and policy entry point.

---

## Journey 6: Support agent views reports in Optimize (full mode)

Authentication (steps 1-2) is shipped; Optimize's authorization enforcement (step 4) and its
policy receipt from Hub (step 3) are not yet implemented — see
[rollout status](./architecture/02-current-state.md#21-rollout-status-at-a-glance).

- Actor: Support agent / analyst
- Goal: View process analytics and reports scoped to their tenant.
- Main steps:
  1. Agent signs into the Optimize UI via the same Enterprise IdP used by Hub and OC.
  2. Optimize's Camunda Security Library validates the token — shipped.
  3. Optimize is designed to load its local policy projection, received from Hub over the same
     distribution channel a `managed` OC uses — not yet implemented.
  4. Optimize evaluates the agent's tenant- and role-based authorization for the requested report
     — today this still runs through Management Identity, not CSL.

Outcome (target): The agent sees only the reports and dashboards their role and tenant permit,
using the same policy model enforced elsewhere in Hub and OC.
