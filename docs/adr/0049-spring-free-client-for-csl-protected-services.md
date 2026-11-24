# ADR-0049: A Spring-free client adds credentials to calls to CSL-protected services

**DRI**: Patrick Wunderlich (p-wunderlich)
**Deciders**: Patrick Wunderlich (p-wunderlich)
**Status**: Accepted (1.4.0)
**Purpose**: Defines how CSL supplies credentials for outgoing calls to CSL-protected services.
**Audience**: CSL maintainers, and OC and Hub engineers who call CSL-protected services.

## Context

In the E4 fan-out ([#755](https://github.com/camunda/camunda-security-library/issues/755)), the
broker calls Hub from a plain Java thread. These calls need OIDC or Basic credentials, and the
broker has no Spring. CSL protected only inbound calls. CSL now has a reusable client for outbound
calls. Later resilience work ([#133](https://github.com/camunda/camunda-security-library/issues/133))
builds on it.

## Decision

**D1. A new module, `client`, in plain Java 8 with no dependency on other CSL modules.**
A broker thread can use `client`, because `client` has no Spring and no CSL model. An ArchUnit test
enforces this. `client` targets Java 8, so that the Java client can use it in #133. The token
request uses the Nimbus OAuth SDK (`oauth2-oidc-sdk`).

**D2. Spring hosts bind named clients under `camunda.security.client.<name>`.**
The properties are a part of `CamundaSecurityLibraryProperties`, and the starter builds
`OutboundCredentialsProviders` with `@ConditionalOnMissingBean`. OC and Hub already bind this class,
so they get the properties without extra wiring. A name selects the credentials, so one process can
call different services or physical tenants.

**D3. The provider has the shape of the Java client's `CredentialsProvider`, and only the caller retries.**
`OutboundCredentialsProvider` has `applyCredentials`, `shouldRetryRequest` and `close`. With the
same shape, #133 can move the Java client to this module without an API break. After a `401`, the
provider gets a new token, but it never sends the request again. A second `POST` can change data a
second time, and only the caller knows if that is safe.

**D4. `client` does not follow three CSL conventions.**
`OutboundCredentialsProvider` is not a `*Port`, because `client` has no domain. The configuration
types are in `client`, not in `api/model/config/`, because `client` must not depend on `api`. They
are immutable final classes, not records, because `client` targets Java 8.

## Alternatives considered

- **Spring Security's OAuth2 client.** It needs Spring, and the broker has no Spring.
- **The client in `api` or `core`.** The broker would then get the full public model.
- **A hand-written token request.** The Nimbus OAuth SDK already does this on Java 8, and it
  supports `private_key_jwt` and mTLS for #133.

## Consequences

- A broker thread gets OIDC and Basic credentials without Spring.
- CSL must version and release one more artifact.
- The Nimbus OAuth SDK comes onto the broker classpath. OC already has it. In #133 it becomes a new
  dependency of the Java client, and its version can conflict with the Nimbus version of a
  customer's Spring Security.
- There are no resilience features until #133. A failing token endpoint affects all callers.

## Source

- [#787](https://github.com/camunda/camunda-security-library/issues/787): the outbound client
- [#871](https://github.com/camunda/camunda-security-library/pull/871),
  [#874](https://github.com/camunda/camunda-security-library/pull/874),
  [#789](https://github.com/camunda/camunda-security-library/pull/789),
  [#797](https://github.com/camunda/camunda-security-library/pull/797): implementation
- Related: [ADR-0003](0003-no-spring-boot-auto-configuration.md),
  [ADR-0021](0021-hand-authored-spring-configuration-metadata.md)
