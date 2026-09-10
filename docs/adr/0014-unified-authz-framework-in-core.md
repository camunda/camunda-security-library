---
status: Accepted
---

# ADR-0014: Unify authorization checking in CSL `core` behind `AuthorizationCheckPort`

**Deciders**: Patrick Wunderlich

## Status

Accepted

## Context

Two consumers need the same authorization decision from different storage layers: the search /
reader layer (Orchestration Cluster and Hub, reading a secondary index) and the zeebe engine
command hot path (reading RocksDB state). Historically each had its own evaluator, and CSL itself
exposed a third, narrower surface:

- CSL shipped a two-port surface — an inbound `ResourcePermissionPort` returning
  `boolean hasPermission(...)`, paired with an outbound `AuthorizationRepositoryPort` that returned
  raw granted-authorization records for the host's store. It answered exactly one shape of question
  and could not say *why* a check failed.
- OC owned the resource-access-control reader framework and the `AuthorizationChecker`
  scope-evaluation kernel, plus the runtime check-spec vocabulary (`Authorization<T>`,
  `SecurityContext`, the authorization-condition types) — all in OC's `security-core` /
  `security-services`, while the port contracts that referenced those types lived in CSL.
- The engine carried `AuthorizationCheckBehavior`, a parallel implementation of the same logical
  evaluation. Two evaluators drift: a bug fixed in one is not fixed in the other.

Unifying meant closing five gaps that `boolean hasPermission(...)` could not express — a rejection
reason rich enough for the engine, a tenant-entity check, property-based authorization (access
derived from resource properties such as a user task's `assignee` or `candidateGroups`), a
Spring-free claims-to-authentication conversion for a consumer that has a raw claims map and no
application context, and a globally-disabled short circuit for the command hot path. It also meant
resolving a name collision: OC's runtime check spec was called `Authorization<T>`, while CSL
already owned a record named `Authorization` for the *granted* record shape.

The question this ADR answers: what single port surface, vocabulary, and gating rule let CSL serve
both the search layer and the zeebe engine from one evaluator, without dragging framework or
host-specific dependencies into a Spring-free `core`?

## Decision

CSL `core` owns the whole authorization-check framework. Everything below is current state.

### 1. `AuthorizationCheckPort` is the single inbound port

`core/port/in/AuthorizationCheckPort.java` carries three `check(...)` overloads, all returning
`Either<AuthorizationRejection, Void>` — `right(null)` when authorized, `left(rejection)` when
denied:

| Overload | Purpose |
|---|---|
| `<T> check(CamundaAuthentication, RequiredAuthorization<T>)` | Scope-based (RBAC) check |
| `<T> check(Map<String, Object> claims, RequiredAuthorization<T>)` | Claims-map variant; converts the claims to a `CamundaAuthentication` internally, then delegates to the scope-based overload |
| `<T> check(CamundaAuthentication, RequiredAuthorization<T>, T resource)` | Property-based check against a concrete resource instance |

No new Maven module: the framework lives in `core`, which is already Spring-free (enforced by
`DomainArchTest`).

`skipChecks()` — "are checks globally disabled?" — is deliberately **not** on the port. It is a
concrete hot-path convenience on `AuthorizationService` with no consumer that calls it through the
interface; lifting it would be speculative (YAGNI). This is settled, not open.

### 2. Vocabulary: *required* versus *granted*

- `RequiredAuthorization<T>` (`core/auth/`) is the runtime check spec — resource type, permission
  type, resource IDs, an optional `Function<T,String>` ID supplier, an optional `Predicate<T>`
  condition, and a transitive flag. It lives in `core` rather than `api` precisely because it
  carries runtime check semantics (`Function`/`Predicate`), not a public data shape.
- `Authorization` (`api/model/authz/`) remains the *granted* record shape.

The pair mirrors the duality at the heart of every check: what the caller needs versus what the
caller holds.

`SecurityContext` (`core/auth/`) bundles an authentication with an authorization condition for one
operation. `AuthorizationCondition` (`core/auth/condition/`) is a **sealed** interface permitting
exactly `SingleAuthorizationCondition` and `AnyOfAuthorizationCondition`; its `authorizations()`
default method is an exhaustive `switch` over the two permitted subtypes, so a pattern-match site
cannot miss a case and no runtime fallthrough exception is needed. `AuthorizationConditions`
supplies the factory helpers.

### 3. Failure types are general-purpose and live in `api`

- `Either<L, R>` (`api/model/`) — a two-variant type, so no consumer depends on
  `io.camunda.zeebe.util.Either`.
- `AuthorizationRejection` (`api/model/authz/`) — a sealed interface with **three** subtypes:
  - `Tenant(tenantId)` — the principal does not have access to the required tenant.
  - `Permission(resourceType, permissionType, resourceId)` — the principal lacks the required
    permission on the resource.
  - `Property(resourceType, permissionType, propertyNames)` — the principal holds no
    property-scoped grant (or no matching evaluator) for any declared resource property.
    `propertyNames` is defensively copied into an unmodifiable, deterministically-ordered set so a
    rejection cannot be mutated after construction and its `toString()`/`equals()` stay stable for
    logging.
- `RejectionAggregator` (`core/authz/`) composes several rejections into one, for OR-semantics
  checks.

### 4. The reader framework and the scope-evaluation kernel live in `core`

`AuthorizationCheck`, `ResourceAccess`, `ResourceAccessChecks`, `ResourceAccessController`,
`ResourceAccessProvider`, `TenantAccess`, `TenantAccessProvider` and `TenantCheck` are CSL types in
`io.camunda.security.core.authz`. They are pure value types and interfaces referencing only
`CamundaAuthentication` and `RequiredAuthorization`, so keeping them outside CSL would leave CSL's
own port contracts referring to types defined elsewhere.

`AuthorizationChecker` (`core/authz/`) is the single scope-evaluation kernel, written against the
outbound port below rather than against any host's search abstraction.

### 5. Two outbound ports, no more

`AuthorizationScopeRepositoryPort` (`core/port/out/`) abstracts the authorization store:

- `findAuthorizedScopes(ownerIds, resourceType, permissionType)` — bulk retrieval for search
  pre-filtering.
- `findAuthorizedPropertyScopes(ownerIds, resourceType, permissionType, propertyNames)` — the
  `PROPERTY`-matcher subset used by the property-based check. It is a `default` method that filters
  `findAuthorizedScopes` in memory, so it changes nothing for hosts that ignore it; hosts with a
  large scope volume per principal are expected to override it with a store-level filtered query,
  otherwise a property check pulls every scope for the `(resourceType, permissionType)` pair. The
  contract the check relies on and does not re-verify: every returned scope has matcher `PROPERTY`
  and a `resourcePropertyName` contained in `propertyNames`.
- `hasAuthorizedScope(ownerIds, resourceType, permissionType, resourceIds)` — point existence check
  for get-by-id operations.
- `findPermissionTypes(ownerIds, resourceType, resourceIds)` — permission discovery for detail
  views.

Every method takes a pre-resolved `Map<EntityType, Set<String>>` of owner IDs rather than a
`CamundaAuthentication`, so the port does not depend on the authentication model; extracting the
relevant principal identities is the caller's job (normally `AuthorizationChecker`).

`MembershipPort` (`core/port/out/`) resolves a principal's mapping-rule, group, role and tenant IDs
through a query that grows along the chain (mapping rules → groups → roles → tenants), matching the
lazy membership resolution of [ADR-0005](0005-lazy-load-authentication-memberships.md).

The engine supplies RocksDB-backed implementations of both; the search layer keeps its
index-backed adapters. `MappingRuleMatcher` already bridges both layers. **Caching is an
adapter-layer concern** — the engine's adapters cache internally (Guava `LoadingCache`) so `core`
stays dependency-free. That moves caching from per-request to per-adapter, which is why engine
per-command performance has to be validated against the authorization benchmark rather than assumed.

### 6. `AuthorizationService` is the default implementation, and every check it routes is RBAC

`AuthorizationService` (`core/authz/`) implements `AuthorizationCheckPort` with two distinct
evaluation paths — scope-based via `AuthorizationChecker`, and property-based via the
`PropertyAuthorizationEvaluator` instances held in `PropertyAuthorizationEvaluatorRegistry`. The
two are not interchangeable: property-based authorization needs the concrete resource instance, so
callers must not route a property check through the scope-based overload.

**Gating rule.** `check(authentication, RequiredAuthorization)` gates **all** checks — including
`resourceType == TENANT` — on `authorizationEnabled` alone. `multiTenancyChecksEnabled` does **not**
participate in the per-check gate; it survives only inside `skipChecks()`, which returns `true` when
authorization *and* multi-tenancy are both globally disabled.

The reason this is spelled out rather than left implicit: deriving a single discriminator
`isTenantCheck = resourceType == TENANT` and routing it to the `multiTenancyChecksEnabled` gate
conflates two independent concerns — RBAC on tenant *entities* (create / update / delete a tenant,
add / remove a member), which is an authorization concern, and tenant *membership* ("may this
principal act within tenant X"), which is not. That conflation produced a bidirectional defect
([#486](https://github.com/camunda/camunda-security-library/issues/486)):

| authorizations | multi-tenancy | Tenant management op | Behaviour |
|---|---|---|---|
| ON | OFF | authorized for anyone (check skipped) | **fail-open** — privilege-escalation shape |
| OFF | ON | rejected (scope check runs) | **fail-closed** regression |

Every caller that reaches the port for a tenant operation passes
`RequiredAuthorization.of(b -> b.resourceType(TENANT).permissionType(X).resourceId("*"))` — the
resource ID is always the wildcard, never a tenant ID to validate membership against. So `TENANT`
is gated identically to every other resource type: one rule, no special case.

**Forward-looking rule.** Tenant *membership* checks must **never** be expressed as
`check(authentication, RequiredAuthorization)` with `resourceType == TENANT` in the expectation of
multi-tenancy gating. Membership stays on `TenantAccessProvider` / `TenantCheck` /
`CamundaAuthentication.authenticatedTenantIds`. If membership ever needs to flow through
`AuthorizationCheckPort`, it must be modelled as an explicit dimension on `RequiredAuthorization`
(for example a tenant ID to validate) — never inferred from the resource type.

A failed `TENANT` RBAC check still returns `AuthorizationRejection.Tenant` rather than `.Permission`
— both map to HTTP 403, and keeping the label avoids gratuitous cross-repo message churn.

### 7. Property-based authorization

`PropertyAuthorizationEvaluator<T>` is an **`api/context/`** interface, so hosts and non-Spring
consumers implement it without touching `core`. Evaluators are looked up by property name in
`PropertyAuthorizationEvaluatorRegistry` (`core/authz/`); the selected evaluator then matches the
concrete resource. Evaluators that inspect engine-internal resource structures (for example a
user-task evaluator) stay in the engine.

### 8. Claims-to-authentication conversion is Spring-free

`TokenClaimsAuthenticationResolver` (`api/context/`) —
`CamundaAuthentication resolve(Map<String,Object> claims)` — is the inbound contract.
`LazyTokenClaimsConverter` (`core/authz/`) implements it: claims map plus `MembershipPort` yields a
`CamundaAuthentication` whose membership chains resolve lazily. The starter carries no parallel
implementation; `OidcTokenAuthenticationConverter` wraps the core class at the Spring boundary and
translates `IllegalArgumentException` into `OAuth2AuthenticationException`.

**Dual-path group resolution:** a `MembershipPort.groupIds()` adapter checks
`Authorization.USER_GROUPS_CLAIMS` in the claims first and falls back to the membership state.

### 9. Assembly: Spring beans for hosts, a plain-Java factory for everyone else

In the starter, `AuthorizationCheckerConfiguration` and `AuthorizationConfiguration`
(`io.camunda.security.spring.authz`) construct the graph as individual beans, reachable through the
`CamundaSecurityAutoConfiguration` umbrella ([ADR-0003](0003-no-spring-boot-auto-configuration.md)).
Each is a plain `@Configuration` carrying a **class-level `@ConditionalOnBean`** on the ingredient it
needs — `AuthorizationScopeRepositoryPort` and `AuthorizationChecker` respectively — with
`@ConditionalOnMissingBean` on the `@Bean` method inside. `AuthorizationConfiguration`'s method-level
condition is `@ConditionalOnMissingBean(AuthorizationCheckPort.class)`, gated on the *interface* so
the library default backs off for any host `AuthorizationCheckPort` implementation, not only an
`AuthorizationService` subclass. Every `PropertyAuthorizationEvaluator` bean in the context is
collected into the registry automatically.

The class-level `@ConditionalOnBean` is a **deliberate addition beyond** the project-wide rule that
every library-supplied default bean carries `@ConditionalOnMissingBean`
(`.claude/docs/conventions.md`, `.claude/docs/guardrails.md`) — it gates the configuration class, not
the bean method, so the convention itself is satisfied by the per-bean condition that is still
present. The reason for the extra gate: a host that supplies no `AuthorizationScopeRepositoryPort`
has not opted into the authorization stack at all, so the beans should not materialise and then fail
on a missing dependency. Overriding an individual bean works exactly as the convention intends. Do
not "normalise" the class-level annotation away on the grounds that conventions.md only mentions
`@ConditionalOnMissingBean`.

**Activation-ordering caveat — a silent failure.** `@ConditionalOnBean` is evaluated when the class
is imported. A host must therefore **not** `@Import` these configurations from the same plain
`@Configuration` that also declares the `AuthorizationScopeRepositoryPort` bean: Spring processes an
`@Import`ed class before the importing class's own `@Bean` methods, so the condition evaluates before
the port is registered and the bean is **silently skipped** — no exception, no log, just an absent
`AuthorizationCheckPort`. The safe activation path is the `CamundaSecurityAutoConfiguration`
umbrella, which as an `@AutoConfiguration` is processed after all regular `@Configuration` classes
and so reliably sees the host-provided port.

The zeebe engine is not a Spring context, so `AuthorizationPortsFactory` (`core/authz/`) captures
the same assembly in plain Java. Its only public method, `create(...)`, takes the outbound ports,
the evaluator list, the configuration flags and the claim configuration, and returns an
`AuthorizationPorts` holder exposing just `AuthorizationCheckPort checkPort()` and
`TokenClaimsAuthenticationResolver claimsResolver()` — both backed by the **same** converter
instance, mirroring the Spring wiring where one converter bean is shared. A non-Spring consumer
therefore depends only on `api` plus `core/port/in` and never names a `core`-internal type. It is a
static factory, not a builder: the argument set is small, fixed and fully required.

The starter deliberately does **not** route through the factory, so the trivial per-`new` assembly
exists in both places. That duplication is the accepted trade-off, not an oversight — see the
boundaries below.

### 10. The webapp filter is a consumer, not a second model

`WebAppAuthorizationCheckFilter` (`io.camunda.security.spring.filter`) runs after Spring Security's
`AuthorizationFilter` on the webapp chain and asks `AuthorizationCheckPort.check(...)` for `ACCESS`
on the resolved web app as a `COMPONENT` resource. Two host-pluggable SPIs sit **alongside** the
port — they are unaffected by everything above:

- `WebAppProviderPort` (`io.camunda.security.spring.spi`) — `Optional<String> webAppFor(HttpServletRequest)`.
  A single-web-app host returns a constant id; a multi-web-app host derives it from the URL path.
  `Optional.empty()` means "not a web-app request" and the filter passes through.
- `WebAppAccessDeniedHandlerPort` (`io.camunda.security.spring.spi`) —
  `void handle(request, response, webApp, authentication)`. The library ships
  `RedirectingWebAppAccessDeniedAdapter`, which redirects to `<contextPath>/<webApp>/forbidden`.

Both SPIs live in the starter rather than `core/port/out` because their signatures speak
`HttpServletRequest`/`HttpServletResponse` and `core` is jakarta-servlet-free by design (enforced by
`DomainArchTest`). Any servlet-coupled SPI must live in the starter for the same reason.

`WebAppAuthorizationFilterConfiguration` wires the filter and is activated by explicit `@Import`
(ADR-0003); the chain configurations inject it via `ObjectProvider`, so a host that has not
registered the prerequisite SPIs sees the chain exactly as before. The global-disable gate
(`camunda.security.authorizations.enabled=false`) is applied in the filter as well as in
`AuthorizationService`, because a host may supply its own `AuthorizationCheckPort` that is unaware
of the flag.

### 11. `core` and `api` are Jackson-free — standing policy

No `com.fasterxml.jackson..` import is permitted in `core` or `api`, annotations included. The
ArchUnit rules `CORE_MUST_NOT_DEPEND_ON_JACKSON` and `API_MUST_NOT_DEPEND_ON_JACKSON` reject the
whole package with no annotation-package exception. `RequiredAuthorization` and `SecurityContext`
therefore carry no `@JsonAutoDetect` / `@JsonProperty` / `@JsonIgnore`.

A host that needs a custom JSON shape for a CSL type **registers a Jackson mixin on its own
`ObjectMapper`** — OC's `MsgPackConverter` does this for both `CamundaAuthentication` and
`RequiredAuthorization`, keeping the MsgPack wire format of
`BatchOperationCreationRecord.authorizationCheck` unchanged. Annotating a CSL record directly is
**not permitted**. The cost of this pattern is that a mixin must track its record's components; a
round-trip serialization test in the host is what catches divergence.

### 12. What stays in the host

`BrokerRequestAuthorizationConverter` (`CamundaAuthentication` → broker claim map) stays in OC. It
depends on `io.camunda.zeebe.auth.Authorization` claim-key constants — a Zeebe wire-protocol
contract — and on OC's engine security config. CSL's port surface deliberately does not cover
claim-to-broker conversion; owning those constants would couple an identity-and-authorization
library to the broker's serialization format.

### Why these particular boundaries

- **One inbound port, not one per question shape.** Scope-based, tenant and property-based checks
  are the same decision reached three ways. A webapp-specific permission port, or a separate engine
  port, would split the authorization model and let semantics drift per call site.
- **`Either<AuthorizationRejection, Void>` rather than `boolean`.** The engine needs to know *why*
  a check failed to produce a correct rejection message; a `boolean` cannot carry it, and the
  richer type is useful to every consumer, not just the engine.
- **One outbound port with four methods, not four ports.** All four queries share the same
  owner-ID resolution context and the same backing store. Splitting them would create seams with no
  architectural benefit.
- **Pre-resolved owner-ID maps on the outbound port.** Passing `CamundaAuthentication` into the
  store contract would tie the host's persistence adapter to the authentication model and force it
  to know how identities are extracted.
- **A port instead of a direct reference to the host's search abstraction.** Putting OC's
  `AuthorizationReader` into `AuthorizationChecker`'s constructor would pull a search dependency
  into a `core` that ArchUnit keeps framework-free.
- **`PropertyAuthorizationEvaluator` in `api`, its registry in `core`.** The interface is
  host-implemented, so it belongs on the public surface; the lookup table is internal machinery.
- **`AuthorizationScopeRepositoryPort` in `core/port/out/`, not `api`.** It is an infrastructure
  contract for implementors of the search/persistence layer, not a model type adopters import.
- **A sealed `AuthorizationCondition`.** Its `authorizations()` method always assumed exactly two
  concrete types; sealing turns a third-party subtype from a runtime failure into a compile error.
- **`skipChecks()` off the port, `multiTenancyChecksEnabled` kept on the service.** Neither is
  speculative surface: the query has a real hot-path caller but no interface consumer, and the flag
  has exactly one remaining use.
- **Duplicated assembly between `AuthorizationPortsFactory` and the starter beans.** Routing the
  Spring beans through `create(...)` would make the factory build its own checker and converter and
  silently discard a host's bean overrides; publishing granular `new*` factory methods would put
  `AuthorizationChecker` / `AuthorizationService` / `LazyTokenClaimsConverter` back onto a public API
  surface — exactly what this design removes. A few duplicated `new` calls are cheaper than either.
  Do not "fix" this.

### Default implementations and override boundaries

| Contract | Default shipped | Override / implement when |
|---|---|---|
| `AuthorizationScopeRepositoryPort` | None — host must register | Always; override `findAuthorizedPropertyScopes` for a store-level property query |
| `MembershipPort` | None — host must register | Always |
| `AuthorizationChecker` | Library default, only once an `AuthorizationScopeRepositoryPort` bean exists | Custom scope evaluation |
| `AuthorizationCheckPort` | `AuthorizationService`, only once an `AuthorizationChecker` bean exists | Host needs different decision semantics entirely |
| `PropertyAuthorizationEvaluator<T>` | None — the registry may legitimately be empty | Per property-scoped resource type; registered beans are collected automatically |
| `WebAppProviderPort` | None — host must register | Always, if the webapp filter is used |
| `WebAppAccessDeniedHandlerPort` | `RedirectingWebAppAccessDeniedAdapter` | 403 JSON, forward to an error page, custom telemetry |

## Consequences

**Positive**

- One scope-evaluation kernel serves both the search layer and the engine; semantic drift between
  two evaluators is structurally prevented rather than policed.
- No new Maven module and no new outbound port contracts — the engine implements two focused
  RocksDB adapters against ports that already existed.
- `Either`, `AuthorizationRejection` and the property-based check are port-contract features
  available to every consumer, not engine-only concessions.
- A non-Spring consumer depends only on `api` plus `core/port/in` and the factory entry point,
  never on a `core`-internal type; Spring and non-Spring paths build the same graph.
- `core` and `api` are Jackson-free at compile time, so adopters consume the public types with no
  Jackson on the classpath. The mixin pattern is uniform across `CamundaAuthentication` and
  `RequiredAuthorization`.
- `AuthorizationCondition` subtypes are compiler-verified exhaustive.
- Both rows of the #486 defect table are fixed: tenant-entity RBAC is enforced whenever
  authorization is enabled, and is not spuriously rejected when it is disabled.
- The webapp filter shares one implementation across hosts; only web-app derivation and the denial
  response are pluggable, and the denial response is a behaviour rather than a property — type-safe,
  testable, unconstrained.
- `AuthorizationChecker` unit tests need no host search plumbing; the outbound port is mocked.

**Negative / accepted trade-offs**

- `core` grows. A dedicated module can be split out later if it becomes unwieldy; at the current
  size the Maven overhead would buy nothing.
- The property-based path is a second evaluation path inside `AuthorizationService`. Callers that
  bypass it get scope-based semantics silently, so the distinction is documented on the class.
- `core` holds no cache. Engine per-command performance depends entirely on adapter-level caching,
  which must be verified against the authorization benchmark rather than assumed.
- The per-`new` assembly is duplicated between `AuthorizationPortsFactory.create(...)` and the
  starter beans.
- The starter's class-level `@ConditionalOnBean` gates go beyond the project-wide
  `@ConditionalOnMissingBean` convention, and they carry an ordering trap that fails **silently**:
  importing the configurations from the same `@Configuration` that declares the scope repository
  yields no `AuthorizationCheckPort` and no error. The umbrella is the only reliable activation path.
- Changes to `LazyTokenClaimsConverter`'s constructor or `convert()` must also update the
  `OidcTokenAuthenticationConverter` wrapper.
- `multiTenancyChecksEnabled` is near-vestigial in `AuthorizationService`, used only by
  `skipChecks()`. That reflects reality — membership does not flow through the port — and the field
  is retained deliberately.
- Engine behaviour changed with the gating fix: tests that passed only because a check was skipped
  (authorization ON, multi-tenancy OFF) now correctly see a 403.
- Third-party code that implemented `AuthorizationCondition` gets a compile error. Intentional; the
  type was never an extension point.
- Adding an abstract method to `AuthorizationCheckPort` breaks every hand-rolled implementer,
  including test doubles.
- Hosts must register a `WebAppProviderPort` and an `AuthorizationCheckPort` before the webapp
  filter activates. There is no "auto-detect web apps from the configured component names" fallback,
  because path-to-component derivation differs between hosts (case sensitivity, prefix stripping,
  scoping) and a baked-in rule would either over-fit one host or hide the decision behind config
  that is harder to debug than a one-method SPI.

## Alternatives Considered

- **Keep the engine's `AuthorizationCheckBehavior` as a parallel evaluator.** Rejected — two
  implementations of one decision diverge, and a bug fixed in one is not fixed in the other. This is
  the reason the unified framework exists at all.
- **A separate engine-authz module with its own port contracts (or splitting `core` into
  `authz-core` + `authn-core`).** Rejected — it duplicates `AuthorizationChecker`, and a new
  identity-state port would only restate the outbound ports that already exist. The engine needs
  both authn and authz concepts, so the split adds Maven overhead with no hygiene gain at this
  scale.

Consolidates records previously numbered 0007, 0009, 0019, 0020 (security-context), 0022 and 0030 (see git history).
