# CSL conditional annotations

The Camunda Security Library ships a set of meta-annotations in the
`io.camunda.security.spring.annotation` package that make it easy for host
applications and CSL-internal configurations to gate Spring beans on
security-related runtime conditions. All annotations are applicable to both
`@Bean` methods and `@Configuration` classes.

> **Dependency:** all annotations live in
> `camunda-security-library-spring-boot-starter`, so hosts that already depend
> on that artifact get them for free.

---

## Quick reference

| Annotation | Activates when |
|---|---|
| [`@ConditionalOnAuthenticationMethod`](#conditionalonauthenticationmethod) | The configured authentication method matches the given value |
| [`@ConditionalOnProtectedApi`](#conditionalonprotectedapi) | `camunda.security.authentication.unprotected-api` is `false` (the default) |
| [`@ConditionalOnUnprotectedApi`](#conditionalonunprotectedapi) | `camunda.security.authentication.unprotected-api` is `true` |
| [`@ConditionalOnInternalUserManagement`](#conditionaloninternalusermanagement) | The configured authentication method is **not** `OIDC` |
| [`@ConditionalOnCamundaGroupsEnabled`](#conditionaloncamundagroupsenabled) | Some users get their groups from Camunda: the method is not OIDC, or an OIDC provider has no groups claim |

---

## `@ConditionalOnAuthenticationMethod`

```java
import io.camunda.security.spring.annotation.ConditionalOnAuthenticationMethod;
import io.camunda.security.api.model.config.AuthenticationMethod;
```

Gates a bean on the value of `camunda.security.authentication.method`. The
condition evaluates to `true` when the configured method (parsed
case-insensitively) equals the `value()` attribute. When the property is **not
set**, the default method (`BASIC`) is assumed.

**Attribute**

| Attribute | Type | Description |
|---|---|---|
| `value` | `AuthenticationMethod` | The required method — `BASIC` or `OIDC`. |

**Examples**

```java
// Register a bean only when OIDC is active
@Bean
@ConditionalOnAuthenticationMethod(AuthenticationMethod.OIDC)
public MyOidcBean oidcBean() { ... }

// Register a configuration class only for BASIC auth
@Configuration
@ConditionalOnAuthenticationMethod(AuthenticationMethod.BASIC)
public class BasicAuthSpecificConfiguration { ... }
```

**Interaction with the string constant**

Internally the annotation reads
`CamundaSecurityFilterChainConstants.AUTHENTICATION_METHOD_PROPERTY`
(`camunda.security.authentication.method`). Prefer `@ConditionalOnAuthenticationMethod`
over `@ConditionalOnProperty(name = "camunda.security.authentication.method", …)` in
host code — it is type-safe and tracks the CSL's default automatically.

---

## `@ConditionalOnProtectedApi`

```java
import io.camunda.security.spring.annotation.ConditionalOnProtectedApi;
```

Activates when the API is **protected** (i.e.
`camunda.security.authentication.unprotected-api` is `false` — the production
default). Use this for beans that must only exist when security enforcement is
on, for example additional authorization filters or audit-log writers.

No attributes.

```java
@Bean
@ConditionalOnProtectedApi
public AuditLogFilter auditLogFilter() { ... }
```

---

## `@ConditionalOnUnprotectedApi`

```java
import io.camunda.security.spring.annotation.ConditionalOnUnprotectedApi;
```

Activates when `camunda.security.authentication.unprotected-api=true`. This is
the **development-mode** condition and should never gate production-critical
beans. It is the logical inverse of `@ConditionalOnProtectedApi`.

No attributes.

```java
// Register a no-op authentication stub only in dev mode
@Bean
@ConditionalOnUnprotectedApi
public DevModeAuthenticationStub devAuthenticationStub() { ... }
```

---

## `@ConditionalOnInternalUserManagement`

```java
import io.camunda.security.spring.annotation.ConditionalOnInternalUserManagement;
```

Activates when the authentication method is **not** `OIDC`. In practice this
means Camunda's internal user management (BASIC auth or unauthenticated dev
mode) is active and the host is responsible for managing users inside its own
data store.

When `method=oidc`, the IdP owns user identities and internal user management
should not run — beans gated by this annotation back off automatically.

No attributes.

```java
@Bean
@ConditionalOnInternalUserManagement
public UserProvisioningService userProvisioningService(final UserRepository users) { ... }
```

---

## `@ConditionalOnCamundaGroupsEnabled`

```java
import io.camunda.security.spring.annotation.ConditionalOnCamundaGroupsEnabled;
```

Activates when some users get their groups from Camunda, i.e. when
`AuthenticationConfiguration#isCamundaGroupsEnabled()` is `true`. That is the
case when either:

- The authentication method is not `OIDC`, **or**
- An OIDC provider has no groups claim. The providers are the
  `camunda.security.authentication.oidc` block when it has a `client-id`, and
  every provider under `providers.oidc.<name>`. A provider without its own
  `groups-claim` uses the one of the `oidc` block. Of several providers with
  the same `issuer-uri` (a trailing slash doesn't matter), only the first
  counts, because only it verifies the tokens.

Several providers with the same `issuer-uri` are not supported for groups, by
intent. A user who logs in through a later provider of that issuer also gets
the groups claim of the first provider. Give each provider its own issuer.

When every provider has a groups claim, the IdPs are the source of truth for
group membership and CSL's internal group management beans should be
suppressed.

With several providers, some users can get their groups from a claim while
others get them from Camunda. `isExternalGroupsEnabled()` tells whether any
provider has a groups claim, and `getGroupsClaim(issuer)` gives the claim for
the tokens of one issuer. See
[ADR-0040](../adr/0040-derive-groups-modes-from-every-oidc-provider.md).

No attributes.

```java
@Bean
@ConditionalOnCamundaGroupsEnabled
public GroupSyncService groupSyncService(final GroupRepository groups) { ... }
```

---

## Combining annotations

The annotations compose naturally — stack multiple conditions on the same bean
or configuration class; all conditions must match for the bean to be created:

```java
// Active only when OIDC is configured AND the API is protected
@Bean
@ConditionalOnAuthenticationMethod(AuthenticationMethod.OIDC)
@ConditionalOnProtectedApi
public OidcAuditInterceptor oidcAuditInterceptor() { ... }
```

---

## Where the annotations live

All annotations are defined in:

```
spring-boot-starter/src/main/java/io/camunda/security/spring/annotation/
├── ConditionalOnAuthenticationMethod.java
├── ConditionalOnCamundaGroupsEnabled.java
├── ConditionalOnInternalUserManagement.java
├── ConditionalOnProtectedApi.java
└── ConditionalOnUnprotectedApi.java
```

They depend on Spring's `@Conditional` mechanism and the property keys exposed
by
[`CamundaSecurityFilterChainConstants`](../../spring-boot-starter/src/main/java/io/camunda/security/spring/security/CamundaSecurityFilterChainConstants.java).
See [Configuration reference in security-filter-chains.md](./security-filter-chains.md#configuration-reference)
for the full property documentation.

