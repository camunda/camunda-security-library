---
status: Draft
---

# The Unified Policy Model

> **Draft, not a proposal.** Discussion input for a workshop with the OC, Hub, and Optimize teams.
> Nothing here is decided — proposals are marked as such, open questions are marked as open.
> `status: Draft`, not `Proposed`: there is no single decision on the table yet.

## 1. Why one model

Six fixed constraints:

- One unified policy model, used by every component.
- **It extends what CSL already ships — this is not a greenfield design.** The building blocks are
  in the codebase today: `Authorization`, `AuthorizationScope`, `AuthorizationResourceType`,
  `PermissionType`, and `AuthorizationResourceMatcher` in
  [`api/model/authz/`](../../api/src/main/java/io/camunda/security/api/model/authz/);
  `AuthorizationCheckPort`, `AuthorizationService`, `AuthorizationChecker`, `MappingRuleMatcher`,
  and `MembershipPort` in `core/`; `ConfiguredRole` / `ConfiguredGroup` / `ConfiguredTenant` /
  `ConfiguredMappingRule` / `ConfiguredAuthorization` in `api/model/config/initialization/`. The
  work is extending these to fit the unified model, not replacing them.
- **The model is not hierarchical, and a role assignment carries its assignment target.** One rule
  set per level: being an admin of the organization does not make you an admin of a workspace inside
  it — that has to be configured additionally. The consequence is that the same subject holds
  different roles in different places, so the place rides on the *assignment* rather than in the
  role name: *(subject, role, assignment target)*. §4.2 has the detail, §8 the term. External
  source: the Hub team's
  [product-strategy#46](https://github.com/camunda/product-strategy/issues/46) specifies that
  *"Hub and Workspaces get a two-layer role model (Hub platform role + per-workspace role)"*. Why
  now: the same initiative lists *"CSL-based APIs for role assignment across Hub, Workspace, OC, and
  PT"* as a dependency on rock-12 / Identity, wanted at the start of 8.11 epic work.
- Authored centrally in Hub, distributed downward to every OC — in **Hub-managed** deployments. Hub
  is not deployed alongside the execution plane: it runs in the management plane and configures each
  execution plane remotely. [`07-deployment-view.md`](../architecture/07-deployment-view.md) §7.1.2
  already draws that split, and Hub's own code encodes it — `ClusterAppType.HUB` is an
  `AppClusterType.MANAGEMENT` app while the orchestration apps it deploys to are `AUTOMATION`,
  reached per request over `cluster_apps.grpc_url` / `rest_url`. So every execution-plane grant Hub
  authors has to cross a wire: propagation is structural, not an optimisation.
  In `oc-standalone` there is no Hub: OC is the local source of truth and authors its own policy
  (see the deployment-strategy table in `AGENTS.md`). Same model, no propagation — journey 7 walks
  that case, and it is in scope, not an exception to the model.
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

What Hub *does* already have is an assignment narrowed to one place:
`project_permissions(user_id, project_id, permission)`, one row per (user, project). It carries a
fixed permission enum where the unified model would carry a Role reference, which makes it the
precedent §4.2's assignment target generalises rather than replaces.

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

  subgraph L2["2 · Assignment target picker"]
    S["Hub · Workspace · OC · PT · Optimize<br/>levels named by the Hub epic;<br/>their CSL representation is open (§4)"]
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

Level 2 is where an assignment target gets picked (§4.2) — the epic's *"one place"* for setting a
group's whole access picture. Which levels appear there is no longer wide open: the Hub team's
[product-strategy#46](https://github.com/camunda/product-strategy/issues/46) names Hub, Workspace,
OC, Physical Tenant, and Optimize, the last as a yes/no boundary rather than a role. What stays open
is how CSL represents them — and §4.1 still asks which of them can carry a policy at all.

## 4. Where policy attaches, and what a role assignment targets

Proposed Hub structure, from a slide, not from code:

```
Organization
 ├── Workspaces
 │   └── Projects
 └── Stage Environments        (dev, test, staging, prod — Hub configures all of them)
     └── Clusters
         └── Physical Tenants
             └── Logical Tenants
```

The **stage environment** level is design intent like the rest of this tree: an organization defines
its stage environments, and each cluster belongs to one of them. Design intent is the operative
phrase — today's Hub contradicts the cardinality, holding stages as four fixed per-project slots
that are n:m against clusters (§4.3 point 2, Q6).

Hub itself sits outside every box from the stage-environment line down (§1): it configures all of
them across a wire. That is why propagation is structural rather than an optimisation, and why
§4.3's missing cluster→engine mapping blocks journeys 2 and 3 rather than merely complicating them.

What a workspace user addresses is a stage environment — *"deploy to test"*. The Cluster / Physical
Tenant / Logical Tenant beneath it are realisation detail whose kind does not matter to them.

### 4.1 Which scopes can carry a policy?

Which of these seven levels — the stage environment included — is a valid attachment point for a
grant, and which is addressing detail? Not every level in a navigation tree is a policy scope.

The containment in the tree is real. A physical tenant lives inside a cluster and owns its own
infrastructure — its own database, its own identity-provider connection — with logical tenants below
it. That isolation is the OC model as the OC team describes it, not something grepped here. What is
code-verified: physical tenant IDs live in `PhysicalTenantIds`
(`cluster/src/main/java/io/camunda/cluster/PhysicalTenantIds.java`), there is always at least
`DEFAULT_PHYSICAL_TENANT_ID` (`"default"`), and partition/routing config consumes them
(`FixedPartition.physicalTenantId`, `PhysicalTenantResolver`).

Physical tenancy is an OC concept, and CSL deliberately never learns about it. CSL speaks only an
opaque **scope** key that the host maps to its own concept, and names the host-facing types
`Scoped*` accordingly (the convention block in `AGENTS.md`; ADR-0009, ADR-0013, ADR-0019).
[`ScopedAuthorizationCheckPortFactory`](../../core/src/main/java/io/camunda/security/core/authz/ScopedAuthorizationCheckPortFactory.java)
hands back one `AuthorizationCheckPort` per scope; OC maps each scope to a physical tenant.

What follows for this question: CSL's logical-tenant check carries a flat ID list —
`TenantCheck(boolean enabled, List<String> tenantIds)` — because the containment lives in host
configuration, not in CSL's types. The containment in the tree is real for addressing, and it
carries no rule inheritance (§4.2): CSL evaluates the rule set as authored for the level it is asked
about, with no resolution step sitting above it.

### 4.2 No inheritance — one rule set per level

Settled, not open: the model is **not hierarchical**. Every level has its own rule set and nothing
flows down either branch. Being an admin of the organization does not make you an admin of a
workspace inside it, nor an admin in `prod` — and being an admin in `dev` says nothing at all about
`prod`. Each of those is its own rule set, and has to be configured additionally. The Hub team's
[product-strategy#46](https://github.com/camunda/product-strategy/issues/46) describes the same
shape from the product side: a group gets *"their Hub role, their role in each Workspace, their role
on each OC, their role on each PT, and their access to Optimize"* — five assignments authored
independently, not one that cascades. The last of those is a different kind, worth flagging:
Optimize is a yes/no boundary rather than a role.

**The consequence: the same subject holds different roles in different places.** A user is admin in
Workspace 1 but just reader in Workspace 2, and reader in Project A of Workspace 1. None of that is
expressible today. So the place a role applies to rides on the *assignment*:

> *(subject, role, assignment target)*

The **assignment target** is the workspace, project, or stage environment an assignment is narrowed
to (§8 defines the term, and says why this note avoids calling it a "scope"). That a stage
environment can itself be targeted is settled design input, not an open question: *admin in dev,
reader in prod*. It generalises something Hub already ships as a fixed rule. camunda-docs' *Deploy a
project* page says of the Production stage *"Only administrators and organization owners can deploy
to this stage"*, and the one organization-level setting Hub defines is
`OrganizationSettingsKey.DEPLOYMENT_POLICY` (`ADMIN_ONLY` / `REVIEW_REQUIRED`) — *who* may deploy
rather than *where*. So stage-differentiated authorization exists today; it is just expressed as
fixed rules rather than as data an assignment could carry. It attaches to the assignment whatever
the subject is: `AuthorizationOwnerType` already spans `USER`, `CLIENT`, `GROUP`, `ROLE` and
`MAPPING_RULE`, so a targeted assignment can name any of those (its `TENANT` and `UNSPECIFIED`
constants are not assignment subjects). #46's primary authoring path picks an IdP group —
*"which IdP group maps to which Hub platform role, which Workspace role"* — with principals
reaching the role through group membership; that is one path onto the tuple, not a restriction on
it.

#46 names the workspace level explicitly and defers *"Fine-grained, project/file-level RBAC"* to a
later cycle. Read precisely, that deferral is about RBAC granularity *inside* a project (files,
resources), which may or may not be the same axis as targeting an assignment *at* a project. So
whether a project can be an assignment target is noted here and left open — not sequenced.

**The alternative we are not taking:** encoding the level in the role name — `workspace-admin`,
`project-admin`, and one more for every level and every flavour. The assignment target belongs on
the assignment, not in the name. (For a sense of scale: CSL ships six bootstrap role IDs in
`DefaultRole` — `admin`, `readonly-admin`, `rpa`, `connectors`, `app-integrations`, `task-worker`.
A `workspace-admin` would be an authored `Role` entity rather than a new constant there, so this is
not a claim about that enum growing; the point is only how quickly role names multiply once the
level lives inside them.)

**Where this gets built.** CSL has no notion of a targeted assignment today, so this is forward
work, and it lands on five surfaces:

| Will need to carry the assignment target | Why |
|---|---|
| [`MembershipPort`](../../core/src/main/java/io/camunda/security/core/port/out/MembershipPort.java) / [`MembershipQuery`](../../core/src/main/java/io/camunda/security/core/port/out/MembershipQuery.java) | Where a role assignment is asked for and answered. `roleIds(MembershipQuery)` (`MembershipPort.java:37`) answers per principal; it will need to answer per *(principal, assignment target)* |
| [`CamundaAuthentication`](../../api/src/main/java/io/camunda/security/api/model/CamundaAuthentication.java) | Carries resolved membership into every check, so a targeted assignment has to survive that trip |
| `ConfiguredRole` and its siblings in [`api/model/config/initialization/`](../../api/src/main/java/io/camunda/security/api/model/config/initialization/) | How assignments are declared at startup; a targeted assignment needs a declaration form |
| The authoring surface | Where an admin picks *(subject, role, assignment target)* — §3.4's level 2, and #46's *"one place"* |
| Propagation | A targeted assignment has to cross the Hub→OC wire and land in the OC projection |

Two of those force a decision rather than an edit. `MembershipPort` is a **shipped outbound contract
with host implementers** — OC, and Optimize's `OptimizeMembershipAdapter` (§2) — so changing its
signature is a breaking change, which by this repo's own rules makes it ADR territory. And
`CamundaAuthentication` (`CamundaAuthentication.java:39-47`) holds membership as flat sibling lists,
`authenticatedRoleIds` beside `authenticatedTenantIds` — a targeted role is precisely what one more
flat list cannot express.

**Direction:** extend membership so that it optionally knows the assignment target. *Optionally* is
load-bearing — an untargeted assignment is the role at the level it is authored at (#46's Hub
platform role), and a targeted one is narrowed to that workspace or project.

**Open — shape, not approach:** whether the optional assignment target rides as a nullable
component of the existing assignment tuple, or as a distinct targeted-assignment record alongside
it. That choice decides how much of the `MembershipPort` contract moves, so it wants settling
before the ADR is written. The stage environment adds a second dimension to the same question:
because an assignment target now spans kinds — workspace, project, stage environment — it is also
open whether the assignment target is a bare ID or a typed *(kind, id)* pair.

There is a fork on the enforcement side too, named here rather than resolved. The execution-plane
check only ever sees the opaque scope key of §4.1, so CSL cannot tell which stage environment a
scope key belongs to. Either a stage-environment assignment is resolved into its member clusters and
physical tenants *before* it goes on the wire, or CSL gains a second host-mapped notion beside the
scope key. The scope key is what creates that fork; it is not a precedent for how targeting works.

One input back to the Hub team: #46's five assignment layers — Hub, Workspace, OC, Physical Tenant,
Optimize — do not name the stage environment. Recorded as an input, not as a correction.

### 4.3 The Workspace → Stage Environment edge — the crux

Under §4.2 nothing flows down, so the question sharpens. Does a Workspace-level assignment —
including engine rules — reach that workspace's assigned stage environments *at all*, or does the
Workspace → Stage Environment edge merely **assign** stage environments to a workspace while rules
stay authored per stage environment? And can a workspace user configure their stage environments at
workspace level at all?

Evidence, strongest first:

1. **Hub's own code states the gap outright.** `RuntimeConfigurationValidationRequest.java:19-20`,
   verbatim: *"`physicalTenantId` identifies the orchestration cluster (engine) holding the
   configuration; `null` unless Hub has an authoritative cluster-to-engine mapping, which it does
   not today."* Not an inference — Hub documenting itself. And because Hub is not co-deployed with
   the execution plane (§1), that mapping is not a detail on the path to the engine: it *is* the
   path.
2. **The stage-environment edge exists — one level too low, and derived rather than authored.**
   `DeploymentStage` is a bare four-constant enum (`DEV, TEST, STAGE, PROD`). The binding lives in
   four unannotated, nullable, non-foreign-key `String` columns on `ProcessApplication` (v2
   *Project*, table `hub_projects`) — `defaultDevClusterId` / `defaultTestClusterId` /
   `defaultStageClusterId` / `defaultProdClusterId` — written per process application through
   `PUT /process-applications/{processApplicationId}/stages`. `Project` (v2 *Workspace*) has no
   cluster reference at all. And a deployment's stage is *derived*, not chosen:
   `ProjectDeploymentService.deriveStage(clusterId, processApplication)` reverse-looks-up the target
   cluster ID against those four columns in a fixed `if/else` order, returns `null` when none
   matches, and the result is stored as `ProjectDeploymentFile`'s nullable `stage` column beside
   `clusterId` and `DeploymentStatus`.

   Two consequences worth naming. The relation is **n:m by design** — Hub's own frontend records it
   as such: *"A cluster assigned to several stages appears once per assignment, since that is a
   supported configuration, and each entry carries the stage it was assigned to"*
   (`runtime-connection-store.ts:25-27`) — while `deriveStage`'s ordered `if/else` silently keeps
   only the first match. And `tags` is not the stage mechanism it can look like: the `['dev',
   'test']` value in the self-managed `camunda.modeler.clusters[*].tags` docs is an example,
   `cluster_tags` is a free-form string bag, and no code reads a tag as a stage. So what is missing
   is not a column but a level: a named grouping of clusters that a grant could name. Sharper
   question: is the existing per-project, stage-keyed edge the right thing to lift into an
   organization-level stage environment and repurpose as a policy scope, or does identity need its
   own n:m assignment?
3. **The org→cluster relation lives outside Hub's schema, and differs per flavour.**
   `Cluster.java`'s full field list — `id, name, namespace, version, authentication,
   authorizationEnabled, created, createdBy, updated, updatedBy, license, apps, tags,
   customProperties, discoveredProperties` — has no `organization_id`, and no stage attribute
   either. Where the relation does live: in self-managed, clusters are declared in configuration
   (`ClusterProperties`, `camunda.modeler.clusters[*]` — which carries neither an organization nor a
   stage field) and synced into the `clusters` table; in SaaS it is a remote Cloud Console call
   keyed by organization, `CloudConsoleService.getClusters(organizationId, token)` filtered by
   `CloudClusterService.getCluster(...)`. SM has exactly one organization by design
   (`04-system-context.md:13`: *"`organization_id` is fixed and the multi-org partitioning is
   present in the model but not operationally relevant"*). So the level a stage environment would
   attach to is represented differently in the two flavours — part of Q6, not a gap in one repo.

Conclusion: not "should we allow it" but "which of these edges do we lift, is that Hub schema work
in scope, and does the lifted edge grant anything or only assign." With no inheritance, that last
part is what decides the other two.

`IdpApplication.java` already joins a Workspace to a cluster and a tenant (`Project project`,
`Folder folder`, non-null `clusterId`, nullable `tenantId`) — but for Intelligent Document
Processing, an unrelated feature (§8's landmine).

### 4.4 Organization-level defaults for the execution plane — configuration, not inheritance

Precedent first: Hub already ships org-level-default-with-per-cluster-override, for credentials.
`Credential` is org-scoped (`organization_id`, `nullable = false`, plus
`credential_organization_id_name_unique_idx`) and carries `sameConfigForAllClusters`, Javadoc
verbatim: *"When `true`, `configJson` is the shared value for every target cluster. When `false`,
config lives per-cluster in `CredentialCluster`."* `CredentialCluster` is `(credential, clusterId,
configJson, secretRefsJson)`. `Cluster.authorizationEnabled` shows Hub already stores a per-cluster
authz-shaped flag. Proven for a non-identity concern; open question is whether identity adopts the
same shape.

Note the tension with §4.2: an organization-level default with a per-cluster override *is* a
hierarchical shape, and §4.2 rules that out for policy. The precedent is proven for configuration,
not adoptable as-is for authorization — a default that silently applies wherever nothing was
authored is inheritance under another name. Inserting the stage environment between organization and
cluster multiplies that tension rather than easing it: it adds one more layer at which a default
could silently apply. §4.4's ruling is unchanged.

Sub-question: does an authorization-level concept get built at all, or get struck from the docs?
The old §5.2's `AuthorizationLevel{ALL, TENANT, PHYSICAL_TENANT}` (§2) is the unimplemented shape it
was reaching for — and under §4.2 it leans towards struck: in a non-hierarchical model whose
assignments already name the workspace, project, or stage environment they apply to, a level
attached to the grant has no work left to do.

### Scope-vs-plane matrix

| Scope | Management | Execution | Analytics |
|---|---|---|---|
| Organization | ? | ? | ? |
| Workspace | ? | ? | ? |
| Project | ? | ? | ? |
| Stage Environment | ? | ? | ? |
| Cluster | ? | ? | ? |
| Physical Tenant | ? | ? | ? |
| Logical Tenant | ? | ? | ? |

Empty cells are the discussion — the artifact most likely to get drawn on in the room. Under §4.2
every cell is independent: none is implied by the row above it, and each has to be authored on its
own. #46's five layers (Hub, Workspace, OC, Physical Tenant, Optimize) read across these rows
closely enough to use — "product" in that framing is a flavour of level, not a row of its own — but
they do not name the Stage Environment row, which is the input back to the Hub team noted in §4.2.
A row that can carry a policy is also a candidate **assignment target** (§4.2), which is what ties
this matrix to the assignment question.

Cross-references: 4.2 → journeys 1, 3, and 5; 4.3 → journey 2 and journey 4; 4.4 → §3.2.

## 5. Further open questions

Numbering continues from §4 — Q1 is §4.1's attachment question, Q2–Q8 here. Q1–Q3 are entangled;
take as one conversation. (§4.2 is no longer one of them: it is a settled constraint plus one open
question about shape, kept there rather than renumbered into here.)

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
  [product-strategy#46](https://github.com/camunda/product-strategy/issues/46) settles the
  *boundary* without settling the substrate: Optimize access is *"Hub-level yes/no access, data
  always scoped to the viewer's own OC/PT permissions"*, so nothing is authored Optimize-side — but
  something there still has to hold that yes/no and derive the data scoping from it.
- **Q5 Mapping-rule matching primitive.** OC: exact match only, the rule is itself a grantable
  principal. Management Identity: `Operator{CONTAINS, EQUALS}` + `MappingRuleType{ROLE, TENANT,
  GROUP}` — OC cannot express `CONTAINS`.
- **Q6 The Hub↔cluster schema work implied by §4.3.** An authoritative cluster→engine mapping (Hub's
  own Javadoc says absent); whether the stage environment becomes a first-class Hub entity that
  groups clusters — replacing the per-project `default*ClusterId` slots and the stage derived from
  the target cluster ID — or identity gets its own assignment table; and if it does become one, who
  enforces the cardinality, since 1:n containment (each cluster in exactly one stage environment) is
  the design intent while today's model is n:m *by design* (`runtime-connection-store.ts:25-27`)
  with `deriveStage` silently resolving ties — so 1:n is a constraint someone has to add, not a
  property that holds. Plus — with *where* the org→cluster relation lives already settled (§4.3
  point 3: configuration in self-managed, Cloud Console in SaaS) — the open part of it: whether
  Hub needs an `organization_id` on `clusters` of its own at all. Hub team owns — a consequence
  of §4, not a second discussion of it.

**Park:**

- **Q7** Property-scoped grants (`AuthorizationResourceMatcher.PROPERTY`) — real,
  implementation-shaped.
- **Q8** Where identity-provider connection configuration lives (org / cluster / physical tenant).
  Spelled out as "identity-provider" deliberately — in Hub, `Idp*` means something else entirely
  (§8). #46 answers the policy half: a customer may point one OC/PT *"directly to their own IdP,
  bypassing the shared model for that boundary"* and have it coexist with shared boundaries in the
  same organization. Where that configuration *lives* is still open.

One divergence to record rather than resolve: the journeys in §6 speak `POLICY_SNAPSHOT`, while #46
specifies Hub calling each OC/PT's own API, *"with per-boundary (not all-or-nothing)
success/failure"* and no introspection API. That is delivery mechanics rather than the authz model
— see [push-vs-pull-policy-propagation.md](./push-vs-pull-policy-propagation.md).

## 6. User journeys

Each ends with what records this produces and what propagates where. The propagation vocabulary —
`PolicyVersion`, `POLICY_SNAPSHOT`, `EngineCommandPort` — is itself unbuilt: it belongs to
[policy-version-change-sets.md](./policy-version-change-sets.md), and
`05-building-block-view.md:405` records `EngineCommandPort` as *"not yet defined in
`core/port/out/`"*. Journeys use it as shared vocabulary, not as shipped mechanics.

The authoritative product-side journey set lives in the Hub team's
[product-strategy#46](https://github.com/camunda/product-strategy/issues/46); the seven below are
CSL's own reading of what those ask of this library.

1. **Org admin sets up Organization-level access after connecting the identity provider.** Connects
   an IdP in Hub → creates a MappingRule matching an IdP claim → assigns a role to what that rule
   matches, targeted at the organization. #46's equivalent maps *"which IdP group maps to which Hub
   platform role, which Workspace role"*. Records: MappingRule, a role assignment in Hub whose
   assignment target is the organization, a `PolicyVersion` bump. Propagates: full
   `POLICY_SNAPSHOT` out of the management plane to every OC in the organization (§1). Note what
   this is *not*: an Organization-level
   assignment is one level's rule set, not a starting point that descends into workspaces (§4.2) —
   the snapshot distributes the authored facts, it does not widen them.

2. **Grant a team runtime access to one cluster's logical tenant.** Walks Organization → Stage
   Environment → Cluster → Physical Tenant → Logical Tenant. Bites on the stage-environment level
   not existing (§4.3 point 2) and on the missing cluster→engine mapping (§4.3 point 1, Q6); the
   org→cluster step above it is not blocked but is represented differently per deployment
   flavour, so an assignment there has two shapes to satisfy (§4.3 point 3). Records: an
   Authorization scoped to the logical tenant. Propagates: via `EngineCommandPort`, once the
   edges above are resolved.

3. **Grant at Workspace level, reaching that workspace's stage environments (including engine
   rules).** The user's question, directly. Unbuildable today — included anyway, because the clicks
   make §4.3 concrete. What this needs: a lift, not an invention. Hub resolves a deployment's stage
   today by reverse-looking-up its target cluster against
   `ProcessApplication.default{Dev,Test,Stage,Prod}ClusterId` — one level below the Workspace, fixed
   to four stages, derived rather than authored, and meant as deployment targets. This journey needs
   a named level instead: stage environments that group clusters, resolvable at Workspace level,
   general in arity, and readable as a policy scope. It is now the test of §4.3's sharpened
   question: with nothing flowing down (§4.2), a Workspace-level assignment reaching that
   workspace's stage environments has to be an authored reach, not an inherited one. #46 confirms
   the requirement is real and product-owned — its two-layer role model gives a group a role *per
   workspace*.

4. **Grant a team Optimize access — blocked three times over.**
   a. The model cannot express it — though #46 says it does not need to express it *as a role*:
      Optimize access is *"a yes/no granted at the Hub level, tied to the OC/PT view permission they
      already hold"*. What is missing is that boundary on the assignment, not a catalogue of
      Optimize resource types.
   b. Optimize could not receive it — no authorization store *today*. The intended substrate is the
      search backend Optimize already runs (Q4), but nothing writes a policy into it, and
      `OptimizeMembershipAdapter` returns `List.of()` for all four membership methods.
   c. Optimize could not enforce it if it did — zero declarative enforcement, every check
      hand-written per REST method, per-definition authz lost in C8.

   Answer: smaller than it first looked, still blocked. The boundary needs no Optimize resource
   catalogue — #46 renders report data *"scoped to their own view permissions"*, derived from OC/PT
   rather than authored in Optimize — but something in Optimize still has to store that yes/no,
   receive it, and enforce it, and none of the three exists today.

5. **Grant Hub-internal workspace access (a Project/Workspace grant) — never leaves Hub.** Contrast
   with journey 3: same word "workspace", but management-plane only, and buildable today as
   `project_permissions`. It is also the closest thing to a shipped assignment target:
   `project_permissions` holds one row per (user, project) — a role held at one place rather than
   organization-wide (§2, §4.2). Points at Q2 — Hub's shape is not a tuple.

6. **Onboard a machine principal / worker.** Client-credentials principal registered → assigned
   Role/Group or matched by a MappingRule on a client claim. Records: Principal (machine),
   Role/Group assignment, `PolicyVersion` bump. Propagates: `POLICY_SNAPSHOT` to the target cluster;
   the engine sees only the resulting permissions.

7. **The same policy, in OC-standalone, without Hub.** No Hub, no `PolicyVersion`, no propagation —
   OC authors and enforces locally. Records and enforcement live entirely in the OC-local
   projection. Tests whether every journey above still makes sense with the Hub half removed.
   Distinct from #46's two-path model, which is a per-boundary opt-out *inside* an organization —
   one OC/PT wired *"directly to their own IdP"* while the rest of the fleet stays shared — rather
   than a Hub-less deployment.

## 7. What CSL owns and what it does not

| CSL owns | CSL does not own |
|---|---|
| The policy model — roles, groups, mapping rules, principals, authorizations | Transport/delivery mechanics between Hub and OC ([hub-oc-data-propagation.md](../hub-oc-data-propagation.md)) |
| The in/out port contracts (`*Port`) | Authoring UI/navigation |
| Check semantics (`AuthorizationCheckPort`, `AuthorizationService`) | Persistence implementation (host-provided adapters) |
| The authz catalogue for OC (ADR-0008) | Whether/how the catalogue extends to Hub or Optimize (§5, Q3) |

One line [product-strategy#46](https://github.com/camunda/product-strategy/issues/46) draws for us:
what a role can actually *do* — role definition, mapping-rule mechanics — belongs to the separate
Unified Custom Roles initiative, while *"CSL-based APIs for role assignment across Hub, Workspace,
OC, and PT"* is what its dependency table asks of this library. The model and the assignment
contract are CSL's; the catalogue of what each role means is not settled here.

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

- **"assignment target"** — in this note, the workspace, project, or stage environment that a single
  role assignment is narrowed to (§4.2). The word *scope* is deliberately not used for it: `core`
  reserves *scope* for the opaque host key that a host maps to its own concept. It is also not the
  "target cluster" /
  "deployment target" sense used elsewhere in this document — hence always the two-word form.
- **"stage environment"** — in this note, the dev/test/staging/production level between Organization
  and Clusters that Hub configures (§4). The shipped surfaces call the same idea a *deployment
  stage*: Hub's `DeploymentStage` enum, four fixed constants bound per process application and
  derived from the target cluster ID, not a level that groups anything. A bare *Environment* is
  never used as a level name here.

Agree on words before models: §4's diagram and §4.2's assignment examples already use "Workspace"
and "Project" in the v2 API sense.
