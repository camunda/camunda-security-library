---
status: Draft
---

# The Unified Policy Model

> **Draft, not a proposal.** Discussion input for a workshop with the OC, Hub, and Optimize teams.
> Nothing here is decided — proposals are marked as such, open questions are marked as open.
> `status: Draft`, not `Proposed`: there is no single decision on the table yet.

## 1. Why one model

Five fixed constraints:

- One unified policy model, used by every component.
- **It extends what CSL already ships — this is not a greenfield design.** The building blocks are
  in the codebase today: `Authorization`, `AuthorizationScope`, `AuthorizationResourceType`,
  `PermissionType`, and `AuthorizationResourceMatcher` in
  [`api/model/authz/`](../../api/src/main/java/io/camunda/security/api/model/authz/);
  `AuthorizationCheckPort`, `AuthorizationService`, `AuthorizationChecker`, `MappingRuleMatcher`,
  and `MembershipPort` in `core/`; `ConfiguredRole` / `ConfiguredGroup` / `ConfiguredTenant` /
  `ConfiguredMappingRule` / `ConfiguredAuthorization` in `api/model/config/initialization/`. The
  work is extending these to fit the unified model, not replacing them.
- Authored centrally in Hub, distributed downward to every OC — in **Hub-managed** deployments. In
  `oc-standalone` there is no Hub: OC is the local source of truth and authors its own policy (see
  the deployment-strategy table in `AGENTS.md`). Same model, no propagation — journey 7 walks that
  case, and it is in scope, not an exception to the model.
- Distribution/transport is not CSL's concern — CSL supplies the model and the in/out ports, not the
  wire format.
- Hub's own management-plane authz is in scope of the unified model.

CSL owns the model and the ports. Not transport, not UI, not storage — full breakdown in §7.

Precedent already in force: [ADR-0008](../adr/0008-authz-enum-ownership-and-layered-usage.md) makes
CSL's authz enums the canonical source for OC's Service, Search, Exporter, and Persistence layers.
This document asks whether that precedent extends past OC.

## 2. Where we are today

One shipped canonical grant shape — CSL's, canonical per ADR-0008 and already mirrored by hosts —
plus three component-local ones, none with a cross-component consumer. Four vocabularies, but not
four peers: the starting point is extending the canonical shape, not choosing between equals.

| Component | Grant shape | Catalogue | Storage | Scoping |
|---|---|---|---|---|
| **CSL** (shipped; OC consumes it) | `(ownerId, ownerType, resourceType, permissionType, scope)` | CSL's own, in [`api/model/authz/`](../../api/src/main/java/io/camunda/security/api/model/authz/): closed enums, 24 `AuthorizationResourceType` × 47 `PermissionType`, matrix-constrained via `getSupportedPermissionTypes()` | Host-provided persistence, behind `AuthorizationScopeRepositoryPort` | `AuthorizationResourceMatcher{UNSPECIFIED, ANY, ID, PROPERTY}` |
| Hub | Fixed role per resource instance: `project_permissions(user_id, project_id, permission)` | `ProjectPermissionLevel{ADMIN, WRITE, READ, COMMENT, NONE}`; role→action matrix (`ProjectOperation`, 28 constants) compiled into an enum, not data | `project_permissions` table | One row per (user, project) |
| Management Identity | Audience-scoped free-form strings (`write:*`, `admin:clusters`) | `ResourceType` record seeded from YAML (`identity.resource-types`) — ships exactly two: `process-definition`, `decision-definition` | Data-seeded | String match |
| Optimize | `RoleType{VIEWER, EDITOR, MANAGER}`, compared by `ordinal()` | None | `data.roles` array nested inside each collection document | Instance-wide YAML flags `AuthorizationType{CSV_EXPORT, ENTITY_EDITOR}` |

**CSL** already owns the canonical authz catalogue — for OC. `security-protocol/README.md:35`:
*"CSL is the canonical catalogue of all possible values. Hosts (including this module) mirror the
values they need and map via `AuthzModelMapper`."* Extending it platform-wide is an extension
question, not a greenfield one.

**Hub** authors no org-level roles at all — it consumes them: `owner`/`admin` from the Auth0 `orgs`
claim (SaaS), or `admin:*` / `admin:clusters` / `admin:catalog` / `write:*` from Management Identity
(SM). No groups, no mapping rules, no service accounts, no outbox, no policy versioning exist in
Hub's schema (`restapi/db/src/main`) today.

**Management Identity**'s migration controllers cover tenants/groups/roles/mapping-rules/memberships,
not `resource_authorizations` — the identity graph migrates, the grants do not.

**Optimize** uses CSL today, for authentication and session storage only.
`OptimizeMembershipAdapter` implements `MembershipPort` with all four methods returning `List.of()`.
No authorization index, table, or store exists; `data.roles` is the only authz data it owns, and
there is nowhere to put a policy. Zero declarative enforcement
(`@PreAuthorize`/`@Secured`/`@RolesAllowed` = 0 files) — every check is hand-written per REST
method. Per-definition authorization was lost in C8: CCSM reduces it to tenant authorization, SaaS
returns `true` unconditionally (3×). Public shares under `/api/external/**` carry no identity at
all. (Current line: `workdir/camunda/optimize`, `io.camunda.optimize`, 8.11 — not the legacy C7
`workdir/camunda-optimize` line.)

**What the old §5.2 described but nothing implements:** `AuthorizationLevel{ALL, TENANT,
PHYSICAL_TENANT}`, org-wide grants authored in Hub, Optimize resource types, and a shared Hub-plane
resource-type enum. That section documented a model that was never built, so these are gaps in the
document, not findings about the code. Its hierarchy edges are picked up in §4.

## 3. The proposed extension

### 3.1 One sentence

A grant is `(owner) × (resource) × (actions) × (scope)` — CSL's shipped shape. The proposal is not a
new model: it is extending that one platform-wide, keeping the tuple and widening the catalogue and
the set of enforcers.

### 3.2 The plane insight

`resourceType` decides who enforces. The catalogue itself is not hypothetical — it ships in CSL as
[`io.camunda.security.api.model.authz.AuthorizationResourceType`](../../api/src/main/java/io/camunda/security/api/model/authz/AuthorizationResourceType.java),
24 constants today, each declaring its own supported `PermissionType`s via
`getSupportedPermissionTypes()`. The table below is not a new catalogue; it is which plane enforces
which entry:

| Resource type | Enforced by |
|---|---|
| `PROCESS_DEFINITION` (ships today) | OC |
| A Hub-plane type (would be added) | Hub, local, never propagated |
| An Optimize type (would be added) | Optimize |

One vocabulary, three enforcers. Precedent in Hub's own code: `ClusterAppType` maps ten apps onto
`AppClusterType{AUTOMATION, MANAGEMENT}` — `IDENTITY`/`HUB` → `MANAGEMENT`;
`ORCHESTRATION`/`OPERATE`/`TASKLIST`/`OPTIMIZE`/`CONNECTORS`/`ZEEBE_BROKER`/`ZEEBE_GATEWAY`/`ADMIN`
→ `AUTOMATION`. A two-way split over deployed apps, not a three-way split over resource types — a
precedent, not proof.

### 3.3 What each component must give up

- **Hub** — fixed roles become derived presets over grant tuples.
- **Management Identity** — free-form strings become catalogued pairs.
- **Optimize** — needs an enforcement point and a projection into its search-backend store (Q4);
  neither exists today.
- **OC** — gains resource types it does not enforce and must ignore safely.
- **CSL** — extends its catalogue and model; the tuple, the ports, and the check semantics stay as
  shipped.

### 3.4 Hub navigation sketch

The question this document started from: *I log into Hub — where do I maintain my policy?* Three
levels.

```mermaid
flowchart LR
  subgraph L1["1 · Organization vocabulary"]
    direction TB
    P["Principals (users, machines)"]
    G["Groups"]
    R["Roles"]
    M["MappingRules"]
  end

  subgraph L2["2 · Scope picker"]
    S["?  PLACEHOLDER  ?<br/>which levels appear here<br/>is the open question of §4"]
  end

  subgraph L3["3 · Authorizations per plane"]
    direction TB
    MG["Management — Hub enforces locally"]
    EX["Execution — propagated to OC"]
    AN["Analytics — propagated to Optimize"]
  end

  P & G & R & M --> S
  S --> MG & EX & AN
```

Level 2 is drawn as a placeholder deliberately. Filling it in would presuppose the answer to §4.1.

## 4. Open question: where does policy attach?

Proposed Hub structure, from a slide, not from code:

```
Organization
 ├── Workspaces
 │   └── Projects
 └── Clusters
     └── Physical Tenants
         └── Logical Tenants
```

To a workspace user, Cluster / Physical Tenant / Logical Tenant are collectively just an
**Environment** — the kind does not matter to them.

### 4.1 Which scopes can carry a policy?

Which of these six levels is a valid attachment point for a grant, and which is addressing detail?
Not every level in a navigation tree is a policy scope.

The containment in the tree is real. A physical tenant lives inside a cluster and owns its own
infrastructure — its own database, its own identity-provider connection — and there is always at
least the default one (`PhysicalTenantIds.DEFAULT_PHYSICAL_TENANT_ID`, `"default"`, in
`cluster/src/main/java/io/camunda/cluster/PhysicalTenantIds.java`, consumed by partition/routing
config via `FixedPartition.physicalTenantId` and `PhysicalTenantResolver`). Logical tenants sit
below it.

Physical tenancy is an OC concept, and CSL deliberately never learns about it. CSL speaks only an
opaque **scope** key that the host maps to its own concept, and names the host-facing types
`Scoped*` accordingly (the convention block in `AGENTS.md`; ADR-0009, ADR-0013, ADR-0019).
[`ScopedAuthorizationCheckPortFactory`](../../core/src/main/java/io/camunda/security/core/authz/ScopedAuthorizationCheckPortFactory.java)
hands back one `AuthorizationCheckPort` per scope; OC maps each scope to a physical tenant.

What follows for this question: CSL's logical-tenant check carries a flat ID list —
`TenantCheck(boolean enabled, List<String> tenantIds)` — because the containment lives in host
configuration, not in CSL's types. Whichever levels turn out to carry a policy, CSL sees only the
resulting scope key and resource IDs, so any inheritance down the tree has to be resolved before it
reaches CSL.

### 4.2 How does inheritance work across the two branches?

Does a grant at Organization flow down both branches? Override/deny at a lower level, or
additive-only?

Recommendation, not a decision: additive-only — far cheaper to reason about and to project into OC.

### 4.3 The Workspace → Environment edge — the crux

Can a Workspace-level policy — including engine rules — apply to that workspace's assigned
environments? Can a workspace user configure their environments at workspace level at all?

Evidence, strongest first:

1. **Hub's own code states the gap outright.** `RuntimeConfigurationValidationRequest.java:19-20`,
   verbatim: *"`physicalTenantId` identifies the orchestration cluster (engine) holding the
   configuration; `null` unless Hub has an authoritative cluster-to-engine mapping, which it does
   not today."* Not an inference — Hub documenting itself.
2. **The environment edge exists — one level too low, wrong flavour.** `ProcessApplication` (v2
   *Project*) has `defaultDevClusterId` / `defaultTestClusterId` / `defaultStageClusterId` /
   `defaultProdClusterId`. `Project` (v2 *Workspace*) has no cluster reference at all.
   `ProjectDeploymentFile` joins `processApplication` + `clusterId` + `DeploymentStage stage` +
   `DeploymentStatus`. Today: environments attach to a Project, as four fixed deployment-target
   defaults — not to a Workspace, not as an identity scope. Sharper question: is the existing
   Project-level, stage-keyed edge the right thing to lift to Workspace level and repurpose as a
   policy scope, or does identity need its own n:m assignment?
3. **The org→cluster column is absent, with a caveat.** `Cluster.java`'s full field list — `id,
   name, namespace, version, authentication, authorizationEnabled, created, createdBy, updated,
   updatedBy, license, apps, tags, customProperties, discoveredProperties` — has no
   `organization_id`. SM has exactly one organization by design (`04-system-context.md:13`:
   *"`organization_id` is fixed and the multi-org partitioning is present in the model but not
   operationally relevant"*), and whether SaaS sources org→cluster from Console is not established
   from this repo. Not a proven gap — we could not find it here.

Conclusion: not "should we allow it" but "which of these edges do we lift, and is that Hub schema
work in scope."

`IdpApplication.java` already joins a Workspace to a cluster and a tenant (`Project project`,
`Folder folder`, non-null `clusterId`, nullable `tenantId`) — but for Intelligent Document
Processing, an unrelated feature (§8's landmine).

### 4.4 Do org-level defaults for the execution plane exist?

Precedent first: Hub already ships org-level-default-with-per-cluster-override, for credentials.
`Credential` is org-scoped (`organization_id`, `nullable = false`, plus
`credential_organization_id_name_unique_idx`) and carries `sameConfigForAllClusters`, Javadoc
verbatim: *"When `true`, `configJson` is the shared value for every target cluster. When `false`,
config lives per-cluster in `CredentialCluster`."* `CredentialCluster` is `(credential, clusterId,
configJson, secretRefsJson)`. `Cluster.authorizationEnabled` shows Hub already stores a per-cluster
authz-shaped flag. Proven for a non-identity concern; open question is whether identity adopts the
same shape.

Sub-question: does an authorization-level concept get built at all, or get struck from the docs?
The old §5.2's `AuthorizationLevel{ALL, TENANT, PHYSICAL_TENANT}` (§2) is the unimplemented shape it
was reaching for.

### Scope-vs-plane matrix

| Scope | Management | Execution | Analytics |
|---|---|---|---|
| Organization | ? | ? | ? |
| Workspace | ? | ? | ? |
| Project | ? | ? | ? |
| Cluster | ? | ? | ? |
| Physical Tenant | ? | ? | ? |
| Logical Tenant | ? | ? | ? |

Empty cells are the discussion — the artifact most likely to get drawn on in the room.

Cross-references: 4.3 → journey 2 and journey 4; 4.4 → §3.2.

## 5. Further open questions

Numbering continues from §4 — Q1 is §4, Q2–Q8 here. Q1–Q3 are entangled; take as one conversation.

**Blocking — decide in the workshop:**

- **Q2 What shape is a grant?** CSL's tuple is shipped, canonical per ADR-0008, already mirrored by
  hosts. Hub's, Management Identity's, and Optimize's shapes are each local to one component with no
  cross-component consumer. Not "pick one of four peers" — "does everyone adopt the shape that is
  already canonical, and what does each give up." CSL delivers the model; CSL's model is the tuple,
  extended rather than replaced.
- **Q3 Does the catalogue stay closed?** Closed enum + host mirrors + `AuthzModelMapper` (ADR-0008,
  shipped, SBE/RocksDB stability constraints) vs. data-seeded registry (Management Identity,
  shipped). Two live precedents — pick one. Leftover from the old "top scope and authority"
  question, now folded into §4: who authors org-level roles, given Hub only reads them from claims
  today and has no table behind them.

**Needs an owner, not a decision:**

- **Q4 How does Optimize store and enforce a policy?** The store is settled: reuse the search
  backend Optimize already runs — Elasticsearch, or OpenSearch where that is the deployed one
  (Optimize supports both, via its `database.type` build profile and
  `OptimizeOpenSearchClientFactory` / `RichOpenSearchClient`). Open is everything around it: no
  authorization index exists today, no declarative enforcement point, non-functional memberships,
  and per-definition authz was lost in C8. Do public shares stay identity-free? Optimize team owns.
- **Q5 Mapping-rule matching primitive.** OC: exact match only, the rule is itself a grantable
  principal. Management Identity: `Operator{CONTAINS, EQUALS}` + `MappingRuleType{ROLE, TENANT,
  GROUP}` — OC cannot express `CONTAINS`.
- **Q6 The Hub↔cluster schema work implied by §4.3.** An authoritative cluster→engine mapping (Hub's
  own Javadoc says absent); whether the Project-level `default*ClusterId` slots get lifted to
  Workspace level and generalised beyond dev/test/stage/prod, or identity gets its own assignment
  table; whether `organization_id` on `clusters` is actually needed or supplied by Console in SaaS.
  Hub team owns — a consequence of §4, not a second discussion of it.

**Park:**

- **Q7** Property-scoped grants (`AuthorizationResourceMatcher.PROPERTY`) — real,
  implementation-shaped.
- **Q8** Where identity-provider connection configuration lives (org / cluster / physical tenant).
  Spelled out as "identity-provider" deliberately — in Hub, `Idp*` means something else entirely
  (§8).

## 6. User journeys

Each ends with what records this produces and what propagates where. The propagation vocabulary —
`PolicyVersion`, `POLICY_SNAPSHOT`, `EngineCommandPort` — is itself unbuilt: it belongs to
[policy-version-change-sets.md](./policy-version-change-sets.md), and
`05-building-block-view.md:405` records `EngineCommandPort` as *"not yet defined in
`core/port/out/`"*. Journeys use it as shared vocabulary, not as shipped mechanics.

1. **Org admin sets up baseline access after connecting the identity provider.** Connects an IdP in
   Hub → creates a MappingRule matching an IdP claim → assigns a default Role/Group. Records:
   MappingRule, Role/Group assignment in Hub, a `PolicyVersion` bump. Propagates: full
   `POLICY_SNAPSHOT` to every OC in the organization.

2. **Grant a team runtime access to one cluster's logical tenant.** Walks Organization → Cluster →
   Physical Tenant → Logical Tenant. Bites on the missing `organization_id` (§4.3 point 3) and the
   missing cluster→engine mapping (§4.3 point 1, Q6). Records: an Authorization scoped to the
   logical tenant. Propagates: via `EngineCommandPort`, once the edges above are resolved.

3. **Grant at Workspace level, applied to that workspace's environments (including engine rules).**
   The user's question, directly. Unbuildable today — included anyway, because the clicks make §4.3
   concrete. What this needs: a lift, not an invention. Hub resolves environments today from
   `ProcessApplication.default{Dev,Test,Stage,Prod}ClusterId` — one level below the Workspace, fixed
   to four stages, meant as deployment targets. This journey needs that resolution at Workspace
   level, general in arity, and readable as a policy scope.

4. **Grant a team Optimize access — blocked three times over.**
   a. The model cannot express it — no Optimize resource types in the catalogue yet.
   b. Optimize could not receive it — no authorization store *today*. The intended substrate is the
      search backend Optimize already runs (Q4), but nothing writes a policy into it, and
      `OptimizeMembershipAdapter` returns `List.of()` for all four membership methods.
   c. Optimize could not enforce it if it did — zero declarative enforcement, every check
      hand-written per REST method, per-definition authz lost in C8.

   Answer: not without an authorization index in that backend, a projection path into it, and an
   enforcement point in Optimize first.

5. **Grant Hub-internal workspace access (a Project/Workspace grant) — never leaves Hub.** Contrast
   with journey 3: same word "workspace", but management-plane only, and buildable today as
   `project_permissions`. Points at Q2 — Hub's shape is not a tuple.

6. **Onboard a machine principal / worker.** Client-credentials principal registered → assigned
   Role/Group or matched by a MappingRule on a client claim. Records: Principal (machine),
   Role/Group assignment, `PolicyVersion` bump. Propagates: `POLICY_SNAPSHOT` to the target cluster;
   the engine sees only the resulting permissions.

7. **The same policy, in OC-standalone, without Hub.** No Hub, no `PolicyVersion`, no propagation —
   OC authors and enforces locally. Records and enforcement live entirely in the OC-local
   projection. Tests whether every journey above still makes sense with the Hub half removed.

## 7. What CSL owns and what it does not

| CSL owns | CSL does not own |
|---|---|
| The policy model — roles, groups, mapping rules, principals, authorizations | Transport/delivery mechanics between Hub and OC ([hub-oc-data-propagation.md](../hub-oc-data-propagation.md)) |
| The in/out port contracts (`*Port`) | Authoring UI/navigation |
| Check semantics (`AuthorizationCheckPort`, `AuthorizationService`) | Persistence implementation (host-provided adapters) |
| The authz catalogue for OC (ADR-0008) | Whether/how the catalogue extends to Hub or Optimize (§5, Q3) |

## 8. Naming appendix

**Landmine:** `Idp*` in Hub means Intelligent Document Processing, not Identity Provider —
`IdpApplication`, `IdpProvider`, `idp_*` tables (`ExtractionEngine`, `IdpDocument`,
`IdpExtractionField`, `idp_document_extraction_field_values`,
`IdpUnstructuredExtractionTestCaseResult`, `IdpConnectorTemplate`). An identity audience will
misread every one of these on sight.

- **Workspace rename, split across layers.** The v2 API speaks `Workspace*`
  (`WorkspaceCreateRequest`, `WorkspaceResult`, `WorkspaceFilter`) and routes
  `/workspaces/{wsId}/projects` via `WorkspaceProjectsV2Controller`. Persistence still calls a
  Workspace a `Project` (entity `Project` → table `projects`); the v2 *Project* is entity
  `ProcessApplication` → table `hub_projects`. `IdpApplication` even carries a
  `ws_migration_original_folder_id` column.
- `tenant` means a logical Camunda tenant in OC; in Hub it appears in only two entities
  (`IdpApplication`, `AzureSyncSettings`).
- `EntityType` means three different things across the repos.
- `START_PROCESS_INSTANCE` (Management Identity) vs. `CREATE_PROCESS_INSTANCE` (OC).
- `RoleType` (Optimize) vs. `Role` (unified model).
- Cross-repo ADR links have drifted: OC's README cites "CSL ADR-0016" for what is
  [ADR-0008](../adr/0008-authz-enum-ownership-and-layered-usage.md) here; Optimize's
  `OptimizeSecurityPathAdapter` cites "ADR-0038" for what is
  [ADR-0018](../adr/0018-optimize-reuses-stateful-oidc-webapp-chain.md). Hygiene note, not a
  question.

Agree on words before models: §4's diagram already uses "Workspace" and "Project" in the v2 API
sense.
