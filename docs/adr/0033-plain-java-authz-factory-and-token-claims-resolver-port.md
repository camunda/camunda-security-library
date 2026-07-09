---
status: Accepted
---

# ADR-0033: Plain-Java authorization factory and claims-resolver port for non-Spring consumers

**Deciders**: Patrick Wunderlich

## Status

Accepted

Extends the authorization surface introduced by
[ADR-0028](0028-unified-authz-framework-in-core.md) and honours the activation model of
[ADR-0008](0008-no-spring-boot-auto-configuration.md). ADR-0007, ADR-0008 and ADR-0028 stand
unchanged; this ADR records how a non-Spring consumer assembles and consumes the authorization graph
without depending on `core`-internal types.

## Context

The unified authorization framework ([ADR-0028](0028-unified-authz-framework-in-core.md)) lives in
`core`, but its assembly — `new AuthorizationService(new AuthorizationChecker(scopeRepo), registry,
flags, new LazyTokenClaimsConverter(...))` — existed **only** as Spring `@Configuration` in the
`spring-boot-starter` (`AuthorizationConfiguration`, `AuthorizationCheckerConfiguration`,
`CamundaAuthenticationBeansConfiguration`).

The Zeebe engine (camunda/camunda#56803) is a consumer of this framework but is **not** a Spring
context. Per [ADR-0008](0008-no-spring-boot-auto-configuration.md), the starter beans are activated
only by explicit host `@Import` and never auto-activate, so a non-Spring consumer cannot use them.
The engine was therefore forced to hand-assemble the graph, naming three coupling points that are
`core`-internal implementation detail rather than public contract:

1. **`AuthorizationService` is `final` with a single public constructor** that takes the
   `core`-internal `AuthorizationChecker` and `LazyTokenClaimsConverter`. There is no plain-Java
   factory, so a consumer must name both internal types to build the service.
2. **The property-based `check(CamundaAuthentication, RequiredAuthorization<T>, T)` overload existed
   only on the concrete `AuthorizationService`**, not on `AuthorizationCheckPort`. A consumer that
   needs property checks had to hold the concrete class.
3. **Claims→authentication conversion existed only as the concrete `core` class
   `LazyTokenClaimsConverter`** — there was no inbound port. The engine depends on this conversion
   both for authorization checks and for tenant resolution, so it named the concrete type throughout.

The goal is that a non-Spring consumer depends only on `api` and `port/in` types.

## Decision

Three additive changes, all backward compatible:

1. **`TokenClaimsAuthenticationResolver` inbound port (in `api/context`).** A single-method port
   `CamundaAuthentication resolve(Map<String, Object> claims)`. `LazyTokenClaimsConverter` implements
   it; the port method delegates to the pre-existing `convert(Map)`, so existing `convert(...)`
   callers are untouched. Placed in `api` (not `core`) so consumers get the framework-free public
   surface for claims-to-authentication conversion. It is intentionally **not** modelled on the
   existing generic `CamundaAuthenticationConverter<T>` (`supports`/`convert`): that contract probes
   a framework-specific authentication object, whereas this port unconditionally resolves an
   already-extracted claims map — different semantics.

2. **Lift the 3-arg property check onto `AuthorizationCheckPort`.** The existing concrete overload is
   marked `@Override`; the interface gains `<T> Either<AuthorizationRejection, Void> check(
   CamundaAuthentication, RequiredAuthorization<T>, T)`. Property-based authorization is now
   expressible against the port. A `check(Map, req, T)` convenience overload was considered and
   dropped (YAGNI — the consumer resolves the authentication once and reuses it).

3. **Plain-Java `AuthorizationServiceFactory` in `core`.** A static-factory (not a builder) whose
   `create(...)` accepts the outbound ports (`AuthorizationScopeRepositoryPort`, `MembershipPort`),
   the `PropertyAuthorizationEvaluatorRegistry`, the config flags, and the claim configuration
   (`usernameClaim`, `clientIdClaim`, `preferUsernameClaim`, and an optional
   `MembershipResolutionContextPropagator` defaulting to identity). It builds the whole graph
   internally and returns an `Authorization` holder exposing both the `AuthorizationCheckPort` and
   the `TokenClaimsAuthenticationResolver`, backed by the **same** converter instance — mirroring the
   shared-converter wiring in Spring. A consumer therefore never names `AuthorizationChecker` or
   `LazyTokenClaimsConverter`.

   **Factory over builder:** the argument set is small, fixed, and fully required (no meaningful
   optional/defaulted combinatorics beyond the propagator, handled by an overload), so a builder adds
   ceremony without value. A static factory keeps the call site a single expression, matching how the
   Spring beans read.

**DRY for the Spring side.** The three starter `@Configuration` classes delegate their construction
step to granular factory building blocks (`newAuthorizationChecker`, `newTokenClaimsConverter`,
`newAuthorizationService`) rather than the all-in-one `create(...)`. This is deliberate: each of the
three remains a **separately `@ConditionalOnMissingBean`-overridable bean** with its existing
`@ConditionalOn*` gating, so a host that overrides, for example, the `AuthorizationChecker` bean
still has it flow into the service. Routing the Spring `authorizationService` bean through the
all-in-one `create(...)` would have made the factory build its own internal checker and converter,
silently ignoring host overrides — a behaviour change. The all-in-one `create(...)` is for the
non-Spring consumer only.

`skipChecks()` is intentionally **not** lifted onto the port. It is a concrete hot-path convenience;
the Zeebe consumer does not call it (its `CslAuthorizationCheck` delegates to the port without
skip-logic), so adding it to the port would be speculative.

## Consequences

**Positive**

- The Zeebe engine (camunda/camunda#56803) can depend only on `api` + `port/in`
  (`AuthorizationCheckPort`, `TokenClaimsAuthenticationResolver`) and the `core` factory entry point,
  never on the internal `AuthorizationChecker` / `LazyTokenClaimsConverter` types.
- Graph assembly is defined once. Spring and non-Spring paths build it identically.
- Property-based authorization is now part of the port contract, available to any consumer.

**Negative / accepted trade-offs**

- `AuthorizationCheckPort` gains an abstract method. Every implementer must provide it; the two
  in-repo test doubles were updated. Any future hand-rolled (non-Mockito) implementer must implement
  it — acceptable for a port that is meant to be implemented by the library, with hosts overriding
  via the whole bean.
- `AuthorizationServiceFactory` exposes both an all-in-one `create(...)` and three granular building
  blocks. The granular methods exist to preserve Spring's per-bean override points; they are a small,
  documented surface, not general-purpose API.

## Alternatives Considered

- **A builder on `AuthorizationService`.** Rejected — the input set is fixed and required; a builder
  adds ceremony without solving any optional-argument problem.
- **Route the Spring `authorizationService` bean through the all-in-one `create(...)`.** Rejected —
  it would make the factory construct its own checker/converter, silently discarding host bean
  overrides (a behaviour change). Granular delegation preserves the override points.
- **Reuse `CamundaAuthenticationConverter<T>` for claims resolution.** Rejected — its
  `supports`/`convert` shape targets framework-specific authentication objects, not a raw claims map;
  the semantics do not fit.
- **Lift `skipChecks()` onto the port.** Deferred — no consumer calls it through the port; adding it
  now would be speculative (YAGNI).
