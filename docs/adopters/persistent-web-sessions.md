# Adopting CSL persistent web sessions

This guide is for host applications (Hub, Orchestration Cluster gateways, future Camunda services) that need server-side persistent HTTP sessions backed by a storage layer the host controls (search index, RDBMS, …). CSL owns the session lifecycle; the host owns the storage adapter.

For the rationale behind this split — why the lifecycle lives in CSL and the storage stays in the host — see [ADR-0012](../adr/0012-session-store-port-and-web-session-ownership.md). For why CSL configuration classes are opt-in rather than auto-configured, see [ADR-0006](../adr/0006-no-spring-boot-auto-configuration.md).

## What CSL provides

`io.camunda.security.spring.session.WebSessionConfiguration` (in `spring-boot-starter`) wires:

- `WebSessionRepository` — Spring Session `SessionRepository` implementation
- `WebSessionMapper` + `WebSessionAttributeConverter` — boundary translation between Spring Session and the host-supplied storage backend
- `persistentWebSessionDeletionTaskExecutor` — scheduled executor that scans for and evicts expired sessions
- `webSessionDeletionUncaughtExceptionHandler` — default uncaught-exception handler for the deletion thread (logs; does not halt the JVM)

Every bean is `@ConditionalOnMissingBean`, so a host can register its own implementation of any one of them and CSL's default backs off.

`WebSessionConfiguration` wires the session *lifecycle* only — it does not install any `SessionRepositoryFilter` itself. Each chain (the default surface and every physical-tenant scope) gets its own explicitly-installed filter that consumes the `WebSessionRepository` bean produced here; see [ADR-0012](../adr/0012-session-store-port-and-web-session-ownership.md) for why filters are installed per chain instead of through a single global one.

`WebSessionConfiguration` is **gated by `@ConditionalOnPersistentWebSessionEnabled`** — it only loads when `camunda.security.session.persistent.enabled=true`.

## What the host provides

| Bean | Why |
|---|---|
| `SessionStorePort` | Storage adapter — translates the `PersistentSession` boundary record to and from the host's storage entity. See [`SessionStorePort` in ports.md](./ports.md#sessionstoreport). |

The host also chooses *when* to activate `WebSessionConfiguration` — typically behind a web/gateway condition (for example OC gates on `@ConditionalOnRestGatewayEnabled` so persistent sessions only wire up when the REST gateway is active).

## Activating the wiring

`WebSessionConfiguration` is **not** registered in CSL's `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`, and it is **not** included in the `CamundaSecurityAutoConfiguration` umbrella. The host activates it explicitly.

**Use `@ImportAutoConfiguration`, not `@Import`.**

```java
@Configuration
@ConditionalOnRestGatewayEnabled                          // example host gate
@ConditionalOnPersistentWebSessionEnabled                 // same as the CSL class — keep them aligned
@ImportAutoConfiguration(WebSessionConfiguration.class)   // NOT @Import
public class HostWebSessionConfiguration {

  @Bean
  public SessionStorePort sessionStorePort(/* host-storage deps */) { ... }

  // Optional: override any of CSL's @ConditionalOnMissingBean defaults below.
}
```

### Why `@ImportAutoConfiguration` and not `@Import`?

Spring parses an `@Import`-targeted `@Configuration` class **before** the importing class's own `@Bean` methods are registered. So if the host writes:

```java
@Configuration
@Import(WebSessionConfiguration.class)            // wrong for override
public class HostWebSessionConfiguration {
  @Bean("webSessionDeletionUncaughtExceptionHandler")
  public UncaughtExceptionHandler hostHandler() { ... }
}
```

Spring registers CSL's default `webSessionDeletionUncaughtExceptionHandler` first (`@ConditionalOnMissingBean` is true at that point — the host's bean has not yet been seen), then tries to register the host's bean — and fails with:

```
BeanDefinitionOverrideException: Invalid bean definition with name
'webSessionDeletionUncaughtExceptionHandler' ... since there is already
[... io.camunda.security.spring.session.WebSessionConfiguration ...] bound.
```

For unnamed beans (`@Bean` of the same type without a fixed name) the failure mode is quieter: CSL's default wins silently and the host override is dead code.

`@ImportAutoConfiguration` queues the import via a `DeferredImportSelector`, so Spring loads `WebSessionConfiguration` in the deferred auto-configuration phase **after** every regular `@Configuration` class (including the importing host class) has had its `@Bean` methods registered. CSL's `@ConditionalOnMissingBean` then evaluates against the full bean graph and correctly backs off in favour of the host's override.

This is the same opt-in path the umbrella `CamundaSecurityAutoConfiguration` documents in its javadoc, applied to a single configuration class.

## Overridable beans

| Bean | CSL default | Common host override |
|---|---|---|
| `webSessionDeletionUncaughtExceptionHandler` (`UncaughtExceptionHandler`) | Logs (does not halt the JVM) | Halt the JVM on a fatal error — e.g. OC uses `FatalErrorHandler.uncaughtExceptionHandler(...)` |
| `webSessionAttributeConverter` (`WebSessionAttributeConverter`) | `SpringBasedWebSessionAttributeConverter` (Java native serialization) | **Recommended for production** — see the hardening note below |
| `webSessionMapper` (`WebSessionMapper`) | Wraps the attribute converter | Custom mapper if you want full control over the `PersistentSession` ↔ Spring Session translation |
| `webSessionRepository` (`WebSessionRepository`) | Default Spring Session implementation backed by `SessionStorePort` | Rarely needed — overriding implies replacing the whole lifecycle |
| `persistentWebSessionDeletionTaskExecutor` (`ScheduledThreadPoolExecutor`) | Single-thread scheduled executor (core pool size 1, core thread timeout enabled) | Replace if you need different scheduling / instrumentation |

For overrides to take effect, activate `WebSessionConfiguration` via `@ImportAutoConfiguration` (see above).

### Hardening: replace the default attribute converter

The default `SpringBasedWebSessionAttributeConverter` uses Java native serialization (`SerializingConverter`/`DeserializingConverter`) for session attribute values. Two consequences:

1. Deserializing attacker-controllable session bytes can be exploited via gadget chains (the threat model is storage tampering, not casual reads).
2. Persisted sessions are brittle to class/package renames and `serialVersionUID` changes.

Hardened production deployments should register their own `WebSessionAttributeConverter` — for example a JSON converter with explicit DTOs, or a `DeserializingConverter` configured with an `ObjectInputFilter` allowlist. See [ADR-0012 §Risks and follow-ups](../adr/0012-session-store-port-and-web-session-ownership.md#risks-and-follow-ups) for the threat-model discussion.

## Property bridge for legacy keys

The canonical activation property is `camunda.security.session.persistent.enabled`. Hosts that ship from legacy OC builds may still see one of:

- `camunda.persistent.sessions.enabled`
- `camunda.tasklist.persistent.sessions.enabled`
- `camunda.tasklist.persistentSessionsEnabled`
- `camunda.operate.persistent.sessions.enabled`
- `camunda.operate.persistentSessionsEnabled`

OC bridges these onto the canonical property via an `EnvironmentPostProcessor` (`PersistentWebSessionPropertiesPostProcessor` in the OC dist). Other hosts that need the same compatibility window can copy that pattern; CSL itself does not bridge.

## Session idle timeout and the activity heartbeat

Two further properties (ADR-0023) apply to **every** session surface, regardless of whether persistent sessions are enabled:

| Property | Type | Default | Effect |
|---|---|---|---|
| `camunda.security.session.max-inactive-interval` | `Duration` | `30m` | How long a session may go without extending activity before it's treated as expired. |
| `camunda.security.session.heartbeat.enabled` | `boolean` | `false` | Off: any non-polling request extends a session — today's behavior, unchanged. On: only a call to the per-scope `POST {basePath}/session/heartbeat` endpoint extends it; ordinary application requests stop counting. |

> [!WARNING]
> **Never set `max-inactive-interval` shorter than your frontend's actual heartbeat cadence, and don't enable `heartbeat.enabled` before your frontend sends heartbeats at all.**
>
> With `heartbeat.enabled=true`, only the heartbeat call itself extends a session's activity. If `max-inactive-interval` is shorter than (or too close to) the interval your frontend actually pings at — commonly every 30–90 seconds — the session will expire on or before the first heartbeat after creation, regardless of how active the user is. This isn't graceful degradation: users get logged out almost immediately and repeatedly, indistinguishable to them from a normal idle timeout, and the feature will appear completely broken rather than misconfigured.
>
> CSL has no way to know your frontend's actual heartbeat cadence — that value lives entirely in client-side JS, never in any CSL config — so this can't be validated precisely. As a heuristic backstop, CSL logs a **WARN** at startup when `heartbeat.enabled=true` is paired with a `max-inactive-interval` under 2 minutes. Treat that WARN as a strong signal something is misconfigured, not proof everything is fine above the floor — set the interval comfortably larger than your frontend's real cadence, several times larger, not just "more than zero."

## OC reference example

OC's wiring lives in `dist/src/main/java/io/camunda/application/commons/identity/WebSessionRepositoryConfiguration.java`. It:

1. Gates on `@ConditionalOnRestGatewayEnabled` and `@ConditionalOnPersistentWebSessionEnabled` so persistent sessions only wire up when the REST gateway is enabled.
2. Activates CSL via `@ImportAutoConfiguration(WebSessionConfiguration.class)`.
3. Supplies the storage backend (Elasticsearch / OpenSearch / RDBMS) and the `SessionStorePort` adapter (`PhysicalTenantSessionStoreAdapter`, built per physical tenant via `PhysicalTenantScopedSessionStorePortProvider` — see [ADR-0012](../adr/0012-session-store-port-and-web-session-ownership.md)).
4. Overrides `webSessionDeletionUncaughtExceptionHandler` with `FatalErrorHandler.uncaughtExceptionHandler(...)` so a fatal error in the deletion thread halts the JVM instead of being swallowed.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `BeanDefinitionOverrideException: ... 'webSessionDeletionUncaughtExceptionHandler' ... already ... WebSessionConfiguration ... bound` at startup | Host used `@Import` instead of `@ImportAutoConfiguration`. See [Activating the wiring](#activating-the-wiring). |
| Host bean registers but the library's default is the one actually wired (no exception) | Same as above, for unnamed `@Bean`s of the same type. Switch to `@ImportAutoConfiguration`. |
| `WebSessionConfiguration` never activates even though `camunda.security.session.persistent.enabled=true` | Host hasn't `@ImportAutoConfiguration`'d the class (or hasn't done so behind an active host condition). The property alone does not activate any CSL class — see ADR-0006. |
| `UnsatisfiedDependencyException: ... 'webSessionRepository' ... 'SessionStorePort' ...` | Host hasn't registered a `SessionStorePort` bean. See [`SessionStorePort`](./ports.md#sessionstoreport). |
| Users get logged out almost immediately after login on a heartbeat-enabled deployment, repeatedly, regardless of activity | `max-inactive-interval` is shorter than (or too close to) the frontend's real heartbeat cadence. See [Session idle timeout and the activity heartbeat](#session-idle-timeout-and-the-activity-heartbeat). Check startup logs for a WARN beginning `camunda.security.session.max-inactive-interval is set to ... with ... heartbeat.enabled=true`. |
| `camunda.security.session.heartbeat.enabled=true has no effect on the '...' surface` at startup | That surface (default or a physical-tenant scope) is running the in-memory session fallback, which has no touch-suppression mechanism of its own — enable `camunda.security.session.persistent.enabled` for that surface, or the flag does nothing there. |
