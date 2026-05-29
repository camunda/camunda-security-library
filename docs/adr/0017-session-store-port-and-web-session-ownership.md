---
status: Accepted
---

# ADR-0017: SessionStorePort contract and CSL ownership of the web-session lifecycle

**Deciders**: @p-wunderlich, @Ben-Sheppard

## Status

Accepted

## Context

OC (the `camunda` monorepo) runs persistent server-side web sessions: a Spring Session
`SessionRepository` (`WebSession`, `WebSessionRepository`, `WebSessionMapper`,
`WebSessionDeletionTask`) backed by either a search index (Elasticsearch/OpenSearch) or RDBMS. CSL
already declared an empty outbound port `SessionStorePort`, signalling that session *storage* was
always intended to be a CSL contract satisfied by a host-provided backend (see
`docs/architecture_docs.md`, "Expose session persistence behind a `SessionStore` port").

Before this decision the session classes lived entirely in OC's `authentication` module and bound
directly to OC search types — `PersistentWebSessionClient`, `PersistentWebSessionEntity`,
`SearchQueryResult`, and `CamundaSearchException`. That coupling kept the session *lifecycle* logic
(expiry rules, change tracking, polling, the deletion scan) inside a host and prevented other
adopters (Hub, future OCs) from reusing it.

This increment (#242, part of the CSL adoption #95) inverts the dependency so CSL owns the session
lifecycle and depends only on the `SessionStorePort` abstraction, while OC keeps its storage layer
and provides the adapter.

## Decision

**CSL owns the session lifecycle classes.** `WebSession`, `WebSessionRepository`,
`WebSessionMapper` (+ `SpringBasedWebSessionAttributeConverter`), `WebSessionAttributeConverter`, and
`WebSessionDeletionTask` move into `spring-boot-starter/` under
`io.camunda.security.spring.session`. They use Spring Session (`org.springframework.session.*`) and
servlet types, so they belong in the starter, not `core/`.

**`SessionStorePort` defines the storage contract** in `core/port/out/` with four operations that
speak only framework-free types:

```java
PersistentSession get(String sessionId);   // null when absent
void upsert(PersistentSession session);
void delete(String sessionId);
List<PersistentSession> getAll();
```

**A framework-free `PersistentSession` record crosses the boundary**, placed in the public `api`
module at `io.camunda.security.api.model.session`. It is part of the adopter-facing surface — hosts
implementing `SessionStorePort` map their storage entity to and from it — so it belongs with the
other public model records rather than buried in `core`. `core` depends on `api`, so the port can
reference it directly. It replaces OC's `PersistentWebSessionEntity` at the seam: `(String id, Long
creationTime, Long lastAccessedTime, Long maxInactiveIntervalInSeconds, Map<String, byte[]>
attributes)`.

**No default `SessionStorePort` implementation ships in CSL.** The host supplies the adapter. OC's
`SessionStoreAdapter` delegates to its existing `PersistentWebSessionClient` and maps
`PersistentSession` ↔ `PersistentWebSessionEntity`.

**CSL provides a host-imported, property-gated `WebSessionConfiguration`.** CSL owns the bean wiring
for the session lifecycle: `WebSessionConfiguration` (`spring-boot-starter`, `@EnableSpringHttpSession`,
gated by `@ConditionalOnPersistentWebSessionEnabled`) exposes the `WebSessionRepository`, `WebSessionMapper`,
`WebSessionAttributeConverter`, and the deletion-task scheduler — each `@ConditionalOnMissingBean`. It is
**not** auto-activated and is deliberately **left out of the `CamundaSecurityAutoConfiguration` umbrella**
(an intentional exception to the "add new configs to the umbrella" convention): the host must `@Import` it
behind its own web/gateway gate, because activation is tied to the OC-only `@ConditionalOnRestGatewayEnabled`
which CSL cannot reference. The deletion scheduler's `Thread.UncaughtExceptionHandler` is an overridable
`@ConditionalOnMissingBean` bean so the host can plug in its own fatal-error handling.

**Enablement uses a new canonical CSL property** `camunda.security.session.persistent.enabled` (bound via a
new `SessionConfiguration` node and checked by CSL's `@ConditionalOnPersistentWebSessionEnabled`). Hosts that
still use legacy enable-keys bridge them onto this property (OC does so via an `EnvironmentPostProcessor`).

**OC retains only host-specific pieces:** the secondary-storage backend clients + index descriptor, the
`SessionStorePort` adapter bean (with the resilience4j upsert retry — see below), the `@ConditionalOnRestGatewayEnabled`
gate, the `FatalErrorHandler`-backed uncaught-exception-handler override, and the legacy-property bridge. OC's
slim `WebSessionRepositoryConfiguration` `@Import`s CSL's `WebSessionConfiguration`.

**CSL gains one dependency:** `spring-session-core` (version managed by the Spring Boot BOM) in
`spring-boot-starter/`. No resilience4j dependency is added to CSL, because retry stays in the OC
adapter.

## Options Considered

### Boundary return type: `List<PersistentSession>` (chosen) vs `SearchQueryResult`

`PersistentWebSessionClient.getAllPersistentWebSessions()` returns OC's
`SearchQueryResult<PersistentWebSessionEntity>`, but `WebSessionRepository` only ever read `.items()`.
The port returns a plain `java.util.List`, keeping `core/` free of `io.camunda.search.*`. The OC
adapter unwraps `.items()` into a `List`.

### Retry placement: keep in OC adapter (chosen) vs move into CSL

The upsert retry inspects `CamundaSearchException` reasons (`CONNECTION_FAILED`,
`SEARCH_CLIENT_FAILED`, …) to decide what is transient. Moving it into CSL would either require a
CSL-side marker exception that the adapter maps onto (more surface), or generalizing to "retry any
`RuntimeException`" (losing the non-transient distinction) — and either way pulls a resilience4j
dependency into the library.

- **Chosen:** keep the retry (and its swallow-and-log-on-exhaustion behaviour) in OC's
  `SessionStoreAdapter`. CSL's `WebSessionRepository.save` calls `SessionStorePort.upsert` directly.
- **Pro:** CSL takes no resilience4j dependency and no search-specific exception knowledge; the
  port contract stays minimal; transient-failure semantics are preserved exactly where the
  search-specific exception type is available.
- **Con:** a future non-OC adopter that wants the same resilience must implement retry in its own
  adapter. Acceptable: resilience policy is genuinely a property of the storage backend, and the
  port already documents that implementations own infrastructure-failure handling.

### Conditional annotation and enablement property

`ConditionalOnPersistentWebSessionEnabled` lives in CSL (`io.camunda.security.spring.annotation`) and
checks the new canonical property `camunda.security.session.persistent.enabled`. The legacy OC keys
(`camunda.persistent.sessions.enabled` plus `camunda.operate.*` / `camunda.tasklist.*` variants) are
**bridged** onto the canonical key by an OC `EnvironmentPostProcessor`, so the new property is the single
source of truth and CSL never references OC-specific keys. The OC-only `@ConditionalOnRestGatewayEnabled`
and secondary-storage gates remain host-side, applied to OC's config that `@Import`s the CSL one.

(Earlier in this increment the wiring and annotation were left entirely in OC. That was revised: CSL now
owns a host-imported `@Configuration`, leaving OC only the genuinely host-specific gates, storage, adapter,
and the legacy-property bridge.)

## Consequences

**Positive:**
- The session lifecycle (expiry rules, change tracking, polling, deletion scan) is now a reusable
  library concern behind a clean port; any adopter can plug in its own storage.
- `core/` stays framework-free (enforced by `DomainArchTest`); the new port and DTO use only
  `java.util`.

**Negative / ongoing obligations:**
- A second trivial mapping appears at the boundary (`WebSession` ↔ `PersistentSession` in CSL, then
  `PersistentSession` ↔ `PersistentWebSessionEntity` in the OC adapter). This is the cost of the
  dependency inversion; both records carry identical fields.
- Changing the `SessionStorePort` signature requires updating every adapter that satisfies it.
- The library and the host share responsibility for the feature: CSL owns the session classes,
  bean wiring (`WebSessionConfiguration`), scheduling, and the enablement property; OC owns the
  storage backends, the `SessionStorePort` adapter (incl. retry), the gateway gate, the uncaught-handler
  override, and the legacy-property bridge. This split must be kept clear (documented in
  `docs/adopters/ports.md`).
- `WebSessionConfiguration` is intentionally excluded from the `CamundaSecurityAutoConfiguration`
  umbrella, deviating from the "register every config in the umbrella" convention, because activation
  must be wrapped by the host's OC-only gateway gate.
