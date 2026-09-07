## 11. Technical Debts, Risks, and Open Design Questions

### Open design questions

These are unresolved design questions that require a dedicated ADR before implementation can proceed:

- **SPI boundaries for OC/engine command creation** (`EngineCommandPort`): still open. Webapp, session, user, and scope provider SPI boundaries have been defined (ADRs 0004, 0009, 0010, 0013, 0014); the engine-command interface is the remaining open design question.
- **Migration path** from current Auth0-based SaaS setup to "Enterprise IdP as SoT" while keeping Auth0 as a private implementation detail — not yet addressed in an ADR.
- **Policy endpoint ownership:** If the endpoints to apply policy changes are public, Hub will not be aware of what a customer applies to OC and will run out of sync. The right ownership boundary is unresolved.
- **Snapshot idempotency:** How can we apply a snapshot multiple times? How could we reset the projections in primary and secondary storage? The Hub → OC/Optimize distribution work for the policy write path makes this a blocking question, not a speculative one.

### Open issues

- **Multiple Hub instances:** The architecture shows a single shared Hub instance in SaaS and a single Hub in Self-Managed full mode. Some customers require multiple Hub instances (e.g. to separate delivery stages). Each Hub instance is an independent CSL deployment; Hub-to-Hub coordination is out of scope. An OC is associated with exactly one Hub at a time; reassignment is an open design question (see above).
- **Satellite components (open scope):** Two satellite runtimes are not yet explicitly covered by CSL:
  - *App Integrations backend* — not yet decided whether it receives IdP configuration via Hub's CSL port model or manages its own auth independently.
  - *Connectors runtime* — same open question at the OC level.
  - The hexagonal port model accommodates both as future CSL consumers (adapter implementations only, no core change). Whether and when to do this is a scope decision outside this document.

### Known debts

**Authorization write path — two separate gaps, not one.** They have different owners and
different evidence trails:

| Gap | Where it lives today | Evidence |
|---|---|---|
| **Engine-side identity authoring** — identity CRUD processors (`GroupCreateProcessor`, `RoleCreateProcessor`, …), `IdentitySetupInitializer`, `PermissionsBehavior`, `AuthorizationEntityValidator` | Still in `zeebe/engine`; deliberately deferred, not overlooked | Epic [#388](https://github.com/camunda/camunda-security-library/issues/388), "Out of scope (deferred)" list |
| **Hub → OC/Optimize policy distribution** | Nowhere yet — nine empty marker ports (below) plus an undefined `EngineCommandPort` | `core/port/in/` + `core/port/out/` — bodies are `{}` |

The same epic is also the source of a related ownership boundary worth stating precisely: the
`PropertyAuthorizationEvaluator` interface and its registry live in CSL `core` (see
[ADR-0014](../adr/0014-unified-authz-framework-in-core.md)), but `UserTaskPropertyAuthorizationEvaluator`
itself stays in `zeebe/engine` — #388 calls it "engine-internal … not a CSL concern." CSL owns the
evaluation *contract*, not every property-specific evaluator that plugs into it.

- **`EngineCommandPort`** is still undefined — zero occurrences in `core/`, `api/`,
  `spring-boot-starter/`, or `validation/`. This is only the remaining **distribution** gap
  (OC → engine policy propagation); the authorization *read* path is delivered — one evaluator
  behind `AuthorizationCheckPort` serves both the gateway/search layer and the zeebe engine (see
  [ADR-0014](../adr/0014-unified-authz-framework-in-core.md), #388).
- **The deployment strategy property still uses an `oc-` prefix** (`oc-standalone`, `oc-managed`)
  and is not consumed anywhere yet — `oc-standalone`/`oc-managed`, `DeploymentStrategy`, and
  `camunda.security.strategy` return no hits across all four modules, and the property is absent
  from the hand-authored `spring-configuration-metadata.json`. `ADR-0003` already records this as
  "Deferred: deployment-strategy activation" — see
  [ADR-0003:189-194](../adr/0003-no-spring-boot-auto-configuration.md).
- **OC authorization write path missing:** the admin section of the OC UI can only read the
  applied policy; there is no authoring path for tenants, roles, groups, mapping rules, or
  authorizations on CSL yet, in either `standalone` or `managed` mode — see
  [rollout status](./02-current-state.md#21-rollout-status-at-a-glance).
- **Hub and Optimize authorization still run through Management Identity:** neither host has cut
  over to CSL's `AuthorizationCheckPort` for authorization decisions — only authentication has
  moved to CSL for these hosts so far — see
  [rollout status](./02-current-state.md#21-rollout-status-at-a-glance).
- **Optimize's policy-receipt path is not implemented:** the design is settled — Optimize receives
  policy over the same Hub → OC snapshot/outbox channel a `managed` OC uses, not a separate
  mechanism — but no mechanism exists yet on either side of it. Optimize's own projection store
  (its Elasticsearch store) is a host-side outbound-adapter concern, not a CSL one. See
  [rollout status](./02-current-state.md#21-rollout-status-at-a-glance).

- **Nine outbound/inbound ports exist only as empty marker interfaces** — bodies are literally
  `{}`, javadoc only, no methods: `PolicyPort`, `PolicyApplyPort`, `TenantPort`,
  `ClusterRegistrationPort`, `ClusterRegistryPort`, `OutboxPort`, `PolicyRepositoryPort`,
  `FeatureTogglePort`, `IdpClientPort`. The contracts exist as placeholders but define no
  behaviour yet. See
  [`docs/adopters/ports.md`](../adopters/ports.md#quick-reference) for the authoritative port
  inventory, which already marks each of these "under development."
- **`InitializationConfiguration`** (`api/model/config/initialization/`) is a bound, documented
  configuration surface — nothing in the repo reads or acts on the users, mapping rules, roles,
  groups, tenants, or authorizations it carries.

---
