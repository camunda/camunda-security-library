# CSL ports reference

The Camunda Security Library is built around a hexagonal architecture. The library defines all
cross-cutting contracts as **port interfaces**; host applications (OC, Hub) plug in implementations
and may override the library's own defaults. This document lists every port, its contract, and where
implementations live.

There are three categories:

| Category | Package | Direction | Description |
|---|---|---|---|
| [Inbound ports](#inbound-ports-coreportin) | `core/port/in/` | Host → library | Use-case contracts the host (or any caller) invokes on the library |
| [Outbound ports](#outbound-ports-coreportout) | `core/port/out/` | Library → host | Contracts the library calls into the host to fetch data or perform I/O |
| [Spring SPI ports](#spring-spi-ports-spring-boot-starterspi) | `spring-boot-starter/spi/` | Library → host | Servlet-layer callbacks the library invokes; live in the starter because they speak `jakarta.servlet` types that the framework-free `core/` module cannot import |

> **Dependency:** all port interfaces ship in `camunda-security-library-core` (inbound / outbound)
> or `camunda-security-library-spring-boot-starter` (Spring SPI). Library-supplied default port
> implementation beans carry `@ConditionalOnMissingBean` so hosts can override individual beans by
> registering their own.

---

## Quick reference

### Inbound

| Port | CSL default implementation | OC example override |
|---|---|---|
| [`OidcProviderConfigurationPort`](#oidcproviderconfigurationport) | `OidcAuthenticationConfigurationRepository` | _(none — CSL default used)_ |
| [`AuthorizationCheckPort`](#authorizationcheckport) | `AuthorizationService` | _(host may register a decorator)_ |
| [`PolicyPort`](#policyport) | _(none — under development)_ | _(none)_ |
| [`PolicyApplyPort`](#policyapplyport) | _(none — under development)_ | _(none)_ |
| [`TenantPort`](#tenantport) | _(none — under development)_ | _(none)_ |
| [`ClusterRegistrationPort`](#clusterregistrationport) | _(none — under development)_ | _(none)_ |

### Outbound

| Port | CSL default implementation | OC example implementation |
|---|---|---|
| [`AdminUserPresencePort`](#adminuserpresenceport) | _(none — host must provide)_ | `AdminUserPresenceAdapter` |
| [`AuthorizationScopeRepositoryPort`](#authorizationscoperepositoryport) | _(none — host must provide)_ | `SearchAuthorizationScopeRepository` |
| [`MembershipPort`](#membershipport) | _(none — host must provide)_ | `NoDBMembershipService`, `DefaultMembershipService` |
| [`SecurityPathPort`](#securitypathport) | _(none — host must provide)_ | `SecurityPathAdapter` |
| [`BasicAuthUserDetailsPort`](#basicauthuserdetailsport) | _(none — host must provide)_ | `UserDetailsAdapter` |
| [`PolicyRepositoryPort`](#policyrepositoryport) | _(none — under development)_ | _(none)_ |
| [`IdpClientPort`](#idpclientport) | _(none — under development)_ | _(none)_ |
| [`SessionStorePort`](#sessionstoreport) | _(none — host must provide)_ | `SessionStoreAdapter` |
| [`OutboxPort`](#outboxport) | _(none — under development)_ | _(none)_ |
| [`ClusterRegistryPort`](#clusterregistryport) | _(none — under development)_ | _(none)_ |
| [`FeatureTogglePort`](#featuretoggleport) | _(none — under development)_ | _(none)_ |

### Spring SPI

| Port | CSL default implementation | OC example override |
|---|---|---|
| [`AdminUserMissingHandlerPort`](#adminusermissinghandlerport) | `RedirectingAdminUserMissingAdapter` | _(none — CSL default used)_ |
| [`WebAppAccessDeniedHandlerPort`](#webappaccessdeniedhandlerport) | `RedirectingWebAppAccessDeniedAdapter` | _(none — CSL default used)_ |
| [`WebAppProviderPort`](#webappproviderport) | _(none — host must provide)_ | `WebAppProviderAdapter` |

---

## Inbound ports (`core/port/in/`)

Inbound ports are the use-case boundary callers invoke on the library. Each port interface lives in
`core/` so it has zero framework dependencies. The default implementation is typically a
`*Service` class in `spring-boot-starter/` exposed as a `@ConditionalOnMissingBean` Spring bean;
hosts that need different behaviour register their own bean of the port type.

---

### `OidcProviderConfigurationPort`

```java
package io.camunda.security.core.port.in;
```

Reads the merged OIDC provider configuration keyed by registration ID. The library merges the flat
`camunda.security.authentication.oidc.*` block with the
`camunda.security.authentication.providers.oidc.*` map at startup; provider entries overwrite the
flat entry on key collision.

**Methods**

```java
OidcConfiguration getOidcAuthenticationConfigurationById(String registrationId);
Map<String, OidcConfiguration> getOidcAuthenticationConfigurations();
```

**CSL default:** `OidcAuthenticationConfigurationRepository`
(`spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/`), exposed via
`OidcBeansConfiguration`.

**OC:** no override — the CSL default is used directly.

---

### `AuthorizationCheckPort`

```java
package io.camunda.security.core.port.in;
```

The unified authorization inbound port (ADR-0026/ADR-0028): "is this principal authorized for this
requirement?" A `RequiredAuthorization` pairs an `AuthorizationResourceType` with a `PermissionType`
and scopes it to resource IDs (and optionally resource property names). The port returns
`Either.right(null)` when authorized and `Either.left(rejection)` when denied. Both the Zeebe engine
data plane and the webapp authorization filter use this port.

**Methods**

```java
<T> Either<AuthorizationRejection, Void> check(
    CamundaAuthentication authentication, RequiredAuthorization<T> authorization);
<T> Either<AuthorizationRejection, Void> check(
    Map<String, Object> claims, RequiredAuthorization<T> authorization);
<T> Either<AuthorizationRejection, Void> check(
    CamundaAuthentication authentication, RequiredAuthorization<T> authorization, T resource);
```

**CSL default:** `AuthorizationService` (`core/`), wired by `AuthorizationConfiguration` when the
host supplies an `AuthorizationScopeRepositoryPort` (from which the library builds an
`AuthorizationChecker`) and a `MembershipPort` (from which the claims converter is built). Backs off
via `@ConditionalOnMissingBean(AuthorizationCheckPort.class)`.

**OC example override:** a host may register its own `AuthorizationCheckPort` bean to decorate the
default — for example to add legacy component-access aliasing before delegating.

---

### `PolicyPort`

```java
package io.camunda.security.core.port.in;
```

Inbound port for queries over the unified policy model (roles, authorizations, mapping rules). Under
active development — no methods defined yet.

---

### `PolicyApplyPort`

```java
package io.camunda.security.core.port.in;
```

Inbound port for applying a policy snapshot received from Hub to the local projection on the OC
side. Under active development — no methods defined yet.

---

### `TenantPort`

```java
package io.camunda.security.core.port.in;
```

Inbound port for tenant lifecycle and lookup operations. Under active development — no methods
defined yet.

---

### `ClusterRegistrationPort`

```java
package io.camunda.security.core.port.in;
```

Inbound port for registering and deregistering Orchestration Clusters against Hub. Under active
development — no methods defined yet.

---

## Outbound ports (`core/port/out/`)

Outbound ports are contracts the library calls into the host to fetch data or perform I/O. Host
applications must provide a bean for every outbound port that the library actually uses at runtime.
Ports marked _under development_ have no methods yet and do not require a host implementation.

---

### `AdminUserPresencePort`

```java
package io.camunda.security.core.port.out;
```

Reports whether an admin user has been provisioned. The admin-user setup filter consults this port
before deciding whether to allow a request through or hand off to
[`AdminUserMissingHandlerPort`](#adminusermissinghandlerport). Hosts may answer from static
configuration, a live database lookup, or any combination.

**Method**

```java
boolean adminUserExists();
```

**CSL default:** none — the host must supply this bean.

**OC example:** `AdminUserPresenceAdapter` in `authentication/` — looks up whether any user with
admin roles exists in the primary data store.

---

### `AuthorizationScopeRepositoryPort`

```java
package io.camunda.security.core.port.out;
```

Supplies the authorization scopes a set of owners hold, so the library's `AuthorizationChecker` (and
thus the default `AuthorizationCheckPort`) can decide access. The library resolves the principal's
owner IDs (user/client plus groups, roles, mapping rules) via `MembershipPort` and passes them
pre-resolved to this port; implementations own only where the scope records come from (search index,
RDBMS, engine state, etc.).

**Methods**

```java
List<AuthorizationScope> findAuthorizedScopes(
    Map<EntityType, Set<String>> ownerIds,
    AuthorizationResourceType resourceType,
    PermissionType permissionType);
boolean hasAuthorizedScope(
    Map<EntityType, Set<String>> ownerIds,
    AuthorizationResourceType resourceType,
    PermissionType permissionType,
    List<String> resourceIds);
Set<PermissionType> findPermissionTypes(
    Map<EntityType, Set<String>> ownerIds,
    AuthorizationResourceType resourceType,
    List<String> resourceIds);
```

`findAuthorizedPropertyScopes(...)` has a default implementation that filters the result of
`findAuthorizedScopes`; override it with a store-level filtered query when a principal may hold many
scopes.

**CSL default:** none — the host must supply this bean.

**OC example:** `SearchAuthorizationScopeRepository` (`security/security-services/` in the
`camunda/camunda` monorepo) — queries the authorization index (search or RDBMS) for the owners'
scopes.

---

### `MembershipPort`

```java
package io.camunda.security.core.port.out;
```

Resolves group, role, tenant, and mapping-rule memberships for a principal. The library's
authentication converters call this port when building a `CamundaAuthentication`, resolving each
membership field independently from a `MembershipQuery`. Hosts own where the data comes from —
search index, RDBMS, in-memory store, etc.

**Methods**

```java
Set<String> mappingRuleIds(MembershipQuery query);
Set<String> groupIds(MembershipQuery query);
Set<String> roleIds(MembershipQuery query);
Set<String> tenantIds(MembershipQuery query);
```

**CSL default:** none — the host must supply this bean.

**OC examples:**
- `NoDBMembershipService` — returns empty memberships; active when there is no database available
  (e.g., in-memory mode).
- `DefaultMembershipService` (`@Primary`) — resolves memberships from the search index / RDBMS.

---

### `SecurityPathPort`

```java
package io.camunda.security.core.port.out;
```

Declares the HTTP path patterns the security filter chains operate on. The library cannot wire its
filter chains without these — API paths, unprotected endpoints, webapp UI paths, web component
identifiers, and static-asset suffixes are all host-specific.

**Methods**

```java
Set<String> apiPaths();
Set<String> unprotectedApiPaths();
Set<String> unprotectedPaths();
Set<String> webappPaths();
Set<String> webComponentNames();

// default implementations provided — override as needed:
default Set<String> unauthenticatedWebappPaths();      // paths the OIDC webapp chain skips auth for
default Set<String> staticResourceSuffixes();           // .css, .js, .png, … (SPA assets)
default Set<String> adminFilterBypassPaths();           // paths admin-user filter passes through
```

Path patterns use Spring Security ant-style syntax (`**` for multi-level, `*` for single-level).
`webComponentNames()` are bare path-segment identifiers, not ant patterns.

**CSL default:** none — the host must supply this bean.

**OC example:** `SecurityPathAdapter` in `authentication/` — returns OC-specific path sets
(e.g., `/v2/**`, `/login/**`, `/operate/**`).

---

### `BasicAuthUserDetailsPort`

```java
package io.camunda.security.core.port.out;
```

Resolves a user by username for HTTP Basic authentication credential verification. The library owns
the Spring Security plumbing — it supplies the `UserDetailsService` (`CamundaUserDetailsService`,
delegating to this port) and a default delegating `PasswordEncoder`, and Spring Boot assembles the
global `AuthenticationManager` from them. The host only provides this scope-agnostic lookup: it
resolves any tenant/scope internally (for example from the request context), so the port carries
**no scope parameter**.

**Method**

```java
CamundaUserDetails loadUser(String username);   // null when no such user exists
```

`CamundaUserDetails` (nested in the port) is a framework-free record:
`(String username, String password)` — the username and the stored password hash the library uses to
verify basic credentials. Returning `null` makes the library throw `UsernameNotFoundException`.

**CSL default:** none — the host must supply this bean. The CSL `UserDetailsService` only activates
when a `BasicAuthUserDetailsPort` bean is present (`@ConditionalOnBean(BasicAuthUserDetailsPort.class)`), the auth
method is `basic`, and no host `UserDetailsService` is already registered.

**Wiring:** `UserConfiguration` (`io.camunda.security.spring.user`, in the
`CamundaSecurityAutoConfiguration` umbrella) registers `camundaUserDetailsService` and a default
`passwordEncoder` (`PasswordEncoderFactories.createDelegatingPasswordEncoder()`), both basic-auth
only and both `@ConditionalOnMissingBean` so a host can override either. See ADR-0021.

**OC example:** `UserDetailsAdapter` in `authentication/` — looks up the user from secondary storage
(`UserServices.getUser`) and returns `new CamundaUserDetails(username, password)`, replacing OC's
previous hand-rolled `CamundaUserDetailsService`.

---

### `PolicyRepositoryPort`

```java
package io.camunda.security.core.port.out;
```

Persists and reads the unified policy projection (organizations, tenants, roles, groups, mapping
rules, principals, authorizations) in local storage. Under active development — no methods defined
yet.

---

### `IdpClientPort`

```java
package io.camunda.security.core.port.out;
```

Communicates with external Identity Providers (OIDC, SAML, and similar protocols). Under active
development — no methods defined yet.

---

### `SessionStorePort`

```java
package io.camunda.security.core.port.out;
```

Stores and retrieves authenticated web-session state. The library owns the session lifecycle — its
`WebSessionRepository` (a Spring Session `SessionRepository` in `spring-boot-starter/`) creates,
loads, expires, and deletes sessions, persisting each one through this port. Hosts own where the
data lives (database, search index, …) and translate the `PersistentSession` boundary record to
their storage model. Implementations are responsible for handling infrastructure failures (for
example retrying transient storage errors and not leaking infrastructure exceptions to the caller).

**Methods**

```java
PersistentSession get(String sessionId);   // null when absent
void upsert(PersistentSession session);
void delete(String sessionId);
List<PersistentSession> getAll();           // used to scan for and evict expired sessions
```

`PersistentSession` (`api/model/session/`) is a framework-free record:
`(String id, Long creationTime, Long lastAccessedTime, Long maxInactiveIntervalInSeconds,
Map<String, byte[]> attributes)` — timestamps in epoch millis, interval in seconds, attribute
values pre-serialized to bytes.

**CSL default:** none — the host must supply this bean.

**Wiring:** CSL provides `WebSessionConfiguration` (`io.camunda.security.spring.session`), which
wires the `WebSessionRepository`, `WebSessionMapper`, `WebSessionAttributeConverter`, and the
expired-session deletion scheduler (all `@ConditionalOnMissingBean`) and enables Spring Session. It
is **not** in the `CamundaSecurityAutoConfiguration` umbrella — the host activates it explicitly
behind whatever web/gateway condition the host needs. Activation is gated by
`@ConditionalOnPersistentWebSessionEnabled` (`camunda.security.session.persistent.enabled=true`).
The deletion thread's `Thread.UncaughtExceptionHandler` is an overridable
`webSessionDeletionUncaughtExceptionHandler` bean.

> **Activate it with `@ImportAutoConfiguration`, not `@Import`.** A direct `@Import` parses CSL's
> class before the host's own `@Bean` methods, so the CSL defaults register first and any host
> override fails with `BeanDefinitionOverrideException` (or silently loses, for unnamed beans).
> `@ImportAutoConfiguration(WebSessionConfiguration.class)` defers loading to the auto-config
> phase, so the host's beans are already in the factory when CSL's `@ConditionalOnMissingBean`
> conditions evaluate. See the [persistent web sessions adopter guide](./persistent-web-sessions.md)
> for the full end-to-end wiring example, the overridable beans, and a hardening note on the
> default attribute converter (which uses Java native serialization and should be replaced in
> production).

**OC example:** OC supplies the `SessionStorePort` bean as `SessionStoreAdapter` in
`authentication/` — it delegates to the persistent web-session storage client (search index or
RDBMS), maps `PersistentSession` ↔ its storage entity, and owns the upsert retry. OC's slim
`WebSessionRepositoryConfiguration` keeps the storage backends, gates on
`@ConditionalOnRestGatewayEnabled`, activates CSL via
`@ImportAutoConfiguration(WebSessionConfiguration.class)`, and overrides
`webSessionDeletionUncaughtExceptionHandler` with a `FatalErrorHandler`-backed handler. Legacy OC
enable-keys are bridged onto `camunda.security.session.persistent.enabled` by an OC
`EnvironmentPostProcessor`.

---

### `OutboxPort`

```java
package io.camunda.security.core.port.out;
```

Records and dispatches outbox events that carry policy changes from Hub to Orchestration Clusters
(see ADR-0001 and ADR-0003). Under active development — no methods defined yet.

---

### `ClusterRegistryPort`

```java
package io.camunda.security.core.port.out;
```

Reads and maintains the registry of known Orchestration Clusters. Under active development — no
methods defined yet.

---

### `FeatureTogglePort`

```java
package io.camunda.security.core.port.out;
```

Evaluates feature toggle values at runtime. Under active development — no methods defined yet.

---

## Spring SPI ports (`spring-boot-starter/spi/`)

Spring SPI ports are callback interfaces the library calls at the servlet layer. They live in the
`spring-boot-starter` module — not `core/` — because their signatures use `jakarta.servlet` types
that the framework-free domain module cannot import.

Like all CSL default beans, defaults are registered with `@ConditionalOnMissingBean`; hosts
override by registering a bean of the port type before the library configuration runs.

---

### `AdminUserMissingHandlerPort`

```java
package io.camunda.security.spring.spi;
```

Decides what to do when the admin-user setup filter detects that no admin user has been provisioned.
Hosts can redirect to a setup wizard, return a JSON payload, forward to a static page, or apply any
other behaviour.

**Method**

```java
void handle(HttpServletRequest request, HttpServletResponse response)
    throws IOException, ServletException;
```

**CSL default:** `RedirectingAdminUserMissingAdapter`
(`spring-boot-starter/src/main/java/io/camunda/security/spring/security/`) — redirects the browser
to `/admin/setup`.

**OC:** no override — the CSL default is used directly.

---

### `WebAppAccessDeniedHandlerPort`

```java
package io.camunda.security.spring.spi;
```

Decides what to do when an authorization filter denies access to a web app. Hosts can return a 403
JSON body, redirect to an error URL, forward to an error page, or apply any other access-denied
behaviour.

**Method**

```java
void handle(
    HttpServletRequest request,
    HttpServletResponse response,
    String webApp,
    CamundaAuthentication authentication)
    throws IOException, ServletException;
```

**CSL default:** `RedirectingWebAppAccessDeniedAdapter`
(`spring-boot-starter/src/main/java/io/camunda/security/spring/security/`) — redirects the browser
to `/webapp/forbidden` (with the `webApp` name appended as a query parameter).

**OC:** no override — the CSL default is used directly.

---

### `WebAppProviderPort`

```java
package io.camunda.security.spring.spi;
```

Resolves which web app a request belongs to. The library's authorization filters call this SPI;
returning `Optional.empty()` signals "this request doesn't belong to a web app" and the filter
treats it as a pass-through. Hub returns a constant; OC derives the web-app name from the URL path.

**Method**

```java
Optional<String> webAppFor(HttpServletRequest request);
```

**CSL default:** none — the host must supply this bean.

**OC example:** `WebAppProviderAdapter` in `authentication/` — extracts the first path segment after
the context path (e.g., `/operate/...` → `"operate"`).

---

## Where implementations live

```
camunda-security-library/
├── core/src/main/java/io/camunda/security/core/port/
│   ├── in/   ← inbound port interfaces
│   └── out/  ← outbound port interfaces
└── spring-boot-starter/src/main/java/io/camunda/security/spring/
    ├── oidc/     ← OidcAuthenticationConfigurationRepository (OidcProviderConfigurationPort default)
    ├── authz/    ← AuthorizationConfiguration (wires the AuthorizationCheckPort default)
    ├── security/ ← RedirectingAdminUserMissingAdapter, RedirectingWebAppAccessDeniedAdapter
    └── spi/      ← Spring SPI port interfaces
```

Host implementations (OC) live in `authentication/src/main/java/io/camunda/authentication/` in the
`camunda/camunda` monorepo.
