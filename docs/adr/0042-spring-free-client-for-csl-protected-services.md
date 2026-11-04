# ADR-0042: A Spring-free client adds credentials to calls to CSL-protected services

**DRI**: Patrick Wunderlich (p-wunderlich)
**Deciders**: Patrick Wunderlich (p-wunderlich)
**Status**: Accepted (1.3)
**Purpose**: Defines how CSL supplies credentials for outgoing calls to CSL-protected services.
**Audience**: CSL maintainers, and OC and Hub engineers who call CSL-protected services.

## Context

In the E4 fan-out ([#755](https://github.com/camunda/camunda-security-library/issues/755)), the
broker calls Hub from a plain Java thread with the JDK `HttpClient`. These calls need OIDC or Basic
credentials, and the broker has no Spring. CSL protects inbound calls, but it gave no help for
outbound calls. This ADR defines a reusable outbound client. This client is only the groundwork
for [#133](https://github.com/camunda/camunda-security-library/issues/133). #133 adds resilience,
`private_key_jwt`, mTLS and the migration of the Java client on top of it.

## Decision

**D1. A new module, `client`, that depends on no other CSL module.**
`client` is plain Java. It targets Java 8, so that the Java client can use it in #133. It uses the
Nimbus OAuth SDK (`oauth2-oidc-sdk`) for the token request, and SLF4J. An ArchUnit test forbids
Spring, Jakarta Servlet and the other CSL modules. Thus a broker thread can use it.

**D2. Spring hosts bind clients through `CamundaSecurityLibraryProperties`.**
Each client has the properties `camunda.security.client.<name>.oidc.*` or `.basic.*`, as a part of
`CamundaSecurityLibraryProperties`. The starter builds the `OutboundCredentialsProviders` bean with
`@ConditionalOnMissingBean`. OC extends this properties class in its own configuration, and Hub
binds it through `CamundaSecurityAutoConfiguration`. Thus both hosts get the properties without
extra wiring.

**D3. The provider contract has the shape of the Java client's `CredentialsProvider`.**
`OutboundCredentialsProvider` has `applyCredentials(CredentialsApplier)` and
`shouldRetryRequest(StatusCode)`, and it extends `AutoCloseable`. With the same shape, #133 can move
the Java client to this module without an API break.

**D4. The caller decides about retries.**
After a `401`, `shouldRetryRequest` gets a new token and tells the caller if a retry can succeed.
The provider never sends a request again. A `POST` is not idempotent, and only the caller knows if
it can send it two times.

**D5. A host uses named clients.**
`OutboundCredentialsProviders` gives the provider for a name. Thus one process can use different
credentials for different services or physical tenants.

**D6. The `client` module does not follow three CSL conventions.**
`OutboundCredentialsProvider` is not a `*Port`, because `client` has no domain. The configuration
types are in `client`, not in `api/model/config/`, because `client` must not depend on `api`. They
are immutable final classes, not records. `client` targets Java 8, while the rest of CSL uses Java
21.

## Alternatives considered

- **Spring Security's OAuth2 client.** Rejected, because it needs Spring, and the broker has no
  Spring.
- **Put the client in `api` or `core`.** Rejected, because the broker would then get the full
  public model.
- **Write the token request by hand with the JDK `HttpClient` and Jackson.** Rejected, because
  the Nimbus OAuth SDK already does it. The SDK also runs on Java 8, and it supports
  `private_key_jwt` and mTLS for #133.
- **Retry inside the provider.** Rejected, because it hides a second `POST` from the caller.
- **A separate `client-spring` module with its own properties class.** Rejected, because OC binds
  `camunda.security.*` in its own configuration. A second binding there is outside that
  configuration, and it adds one more artifact.

## Consequences

- A broker thread gets OIDC and Basic credentials without Spring.
- CSL must version and release one more artifact.
- `oauth2-oidc-sdk` and its dependencies come onto the broker classpath. OC already has them.
- For #133, the Nimbus OAuth SDK becomes a new dependency of the Java client. Its version can
  conflict with the Nimbus version of a customer's Spring Security.
- The starter depends on `client`. Its properties type repeats the shape of the configuration
  types.
- There are no resilience features until #133. A failing token endpoint affects all callers.

## Source

- [#787](https://github.com/camunda/camunda-security-library/issues/787): the outbound client
- [#789](https://github.com/camunda/camunda-security-library/pull/789): implementation
- [#133](https://github.com/camunda/camunda-security-library/issues/133): later resilience work
- Related: [ADR-0003](0003-no-spring-boot-auto-configuration.md),
  [ADR-0021](0021-hand-authored-spring-configuration-metadata.md)
