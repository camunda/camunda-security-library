# CSL OIDC Authorization Request Resolver — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift OC's `ClientAwareOAuth2AuthorizationRequestResolver` into CSL as the default `OAuth2AuthorizationRequestResolver` bean for the OIDC webapp chain, honouring the existing `OidcConfiguration.resource` and `authorize_request.additional_parameters` properties. The bean is `@ConditionalOnMissingBean` so hosts (including OC today) keep winning.

**Architecture:** New final class `CamundaOidcAuthorizationRequestResolver` in `io.camunda.security.spring.oidc` that takes a `ClientRegistrationRepository` plus a `Map<String, OidcConfiguration>` (the merged flat-plus-providers sources, identical to what `clientRegistrationRepository` already builds). Caches a `DefaultOAuth2AuthorizationRequestResolver` per registrationId; the customizer injects `additional_parameters` and `resource`. Registered as a `@Bean @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)` in `OidcBeansConfiguration`. The flat-plus-providers merge is extracted into a shared private static helper so both beans see the same map.

**Tech Stack:** Java 21, Spring Boot 4, Spring Security 6/7, Spring Security OAuth2 Client, JUnit 5, Mockito, AssertJ.

**Branch:** `feat/oidc-authorization-request-resolver` (already created from `main`; the design spec is the only commit so far).

**Reference files:**
- Spec: `docs/superpowers/specs/2026-05-20-csl-oidc-authorization-request-resolver-design.md`
- OC implementation to lift: `/Users/ben.sheppard/code/camunda/authentication/src/main/java/io/camunda/authentication/config/ClientAwareOAuth2AuthorizationRequestResolver.java`
- Wiring target: `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java`
- Properties model: `api/src/main/java/io/camunda/security/api/model/config/oidc/OidcConfiguration.java` and `AuthorizeRequestConfiguration.java`
- Existing hook test to update: `spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappAuthorizationRequestResolverHookTest.java`

---

## File Structure

**Created:**
- `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolver.java` — the resolver class
- `spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolverTest.java` — unit tests for the resolver

**Modified:**
- `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java` — extract `buildOidcSources` helper; add `oauth2AuthorizationRequestResolver` `@Bean`
- `spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/OidcBeansConfigurationTest.java` — add default-wiring + host-override tests
- `spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappAuthorizationRequestResolverHookTest.java` — flip the `chainBuildsWithoutHostResolver` assertion to expect CSL's default
- `docs/adopters/security-filter-chains.md` — new sub-section between line 280 (end of "Disabling the UserInfo fetch") and line 282 (start of "OIDC groups claim extraction")

---

## Task 1: Extract `buildOidcSources` helper (pure refactor)

**Files:**
- Modify: `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java` (lines 226–256, the `clientRegistrationRepository` `@Bean`)

This is a pure refactor with no behaviour change. Existing tests must still pass without modification.

- [ ] **Step 1: Add the new private static helper above `clientRegistrationRepository`**

Insert this method directly above the `@Bean` annotation on line 226 (i.e. between the closing brace of `hasJwtSource(...)` on line 224 and the `@Bean` on line 226):

```java
  /**
   * Merges the flat {@code authentication.oidc.*} block and the {@code
   * authentication.providers.oidc.*} map into a single {@link OidcConfiguration} map keyed by
   * registrationId. The flat block contributes one entry under {@code flat.getRegistrationId()} when
   * {@code clientId} is set; provider entries are put on top so a colliding provider id overwrites
   * the flat entry. Identical merge semantics to OC's {@code OidcAuthenticationConfigurationRepository}.
   */
  static Map<String, OidcConfiguration> buildOidcSources(
      final AuthenticationConfiguration authentication) {
    final OidcConfiguration flat = authentication.getOidc();
    final Map<String, OidcConfiguration> providers = authentication.getProviders().getOidc();
    final Map<String, OidcConfiguration> sources = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      sources.put(flat.getRegistrationId(), flat);
    }
    sources.putAll(providers);
    return sources;
  }
```

(Package-private so the resolver `@Bean` can call it; `static` because it has no instance state.)

- [ ] **Step 2: Replace the inline merge in `clientRegistrationRepository`**

In `clientRegistrationRepository(...)`, replace lines 231–241 (everything from `final OidcConfiguration flat = authentication.getOidc();` through `sources.putAll(providers);`) with a single call. The resulting method body should read:

```java
  @Bean
  @ConditionalOnMissingBean
  public ClientRegistrationRepository clientRegistrationRepository(
      final CamundaSecurityLibraryProperties properties) {
    final var authentication = properties.getAuthentication();
    final Map<String, OidcConfiguration> sources = buildOidcSources(authentication);

    if (sources.isEmpty()) {
      throw new IllegalStateException(
          "Cannot build ClientRegistrationRepository: set"
              + " camunda.security.authentication.oidc.client-id (with issuer-uri or explicit"
              + " endpoints), or one or more"
              + " camunda.security.authentication.providers.oidc.<id>.* entries.");
    }

    final var registrations =
        sources.entrySet().stream()
            .map(e -> buildClientRegistration(e.getKey(), e.getValue()))
            .toList();
    return new InMemoryClientRegistrationRepository(registrations);
  }
```

- [ ] **Step 3: Run the existing client-registration tests**

```
mvn -pl spring-boot-starter test -Dtest=OidcBeansConfigurationClientRegistrationTest
```

Expected: `BUILD SUCCESS` — every existing test passes unchanged.

- [ ] **Step 4: Commit**

```
git add spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java
git commit -m "refactor(spring-boot-starter): extract buildOidcSources helper"
```

(Body explaining the why is optional for a pure refactor of this size — the header tells the story.)

---

## Task 2: TDD — `CamundaOidcAuthorizationRequestResolver` class

**Files:**
- Create: `spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolverTest.java`
- Create: `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolver.java`

Strict TDD: write the test file with **all** unit-test cases first (they all fail because the class doesn't exist), then implement the class to make them pass.

- [ ] **Step 1: Write the failing unit test file**

Create the file with the following exact contents:

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.config.oidc.AuthorizeRequestConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Unit tests for {@link CamundaOidcAuthorizationRequestResolver}. The resolver lifts OC's
 * per-registration customizer logic into CSL: it adds {@code additional_parameters} and {@code
 * resource} (RFC 8707) to the OAuth2 authorization request when configured on the matching {@link
 * OidcConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class CamundaOidcAuthorizationRequestResolverTest {

  private static final String REGISTRATION_ID = "test-oidc";
  private static final String AUTHORIZATION_REQUEST_URI =
      "/oauth2/authorization/" + REGISTRATION_ID;

  @Mock private ClientRegistrationRepository clientRegistrationRepository;

  private ClientRegistration clientRegistration;

  @BeforeEach
  void setUp() {
    clientRegistration =
        ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("test-client")
            .clientSecret("test-secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/login/oauth2/code/" + REGISTRATION_ID)
            .scope("openid")
            .authorizationUri("http://idp.example.com/auth")
            .tokenUri("http://idp.example.com/token")
            .build();
  }

  @Test
  void shouldReturnNullWhenPathDoesNotMatchAuthorizationRequestBaseUri() {
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", "/some/other/path");

    assertThat(resolver.resolve(request)).isNull();
  }

  @Test
  void shouldReturnNullWhenRegistrationIdArgIsBlank() {
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    assertThat(resolver.resolve(request, "")).isNull();
    assertThat(resolver.resolve(request, null)).isNull();
  }

  @Test
  void shouldThrowWhenRegistrationIdIsUnknownToTheRepository() {
    when(clientRegistrationRepository.findByRegistrationId("missing")).thenReturn(null);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/missing");

    assertThatThrownBy(() -> resolver.resolve(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid Client Registration with ID 'missing'");
  }

  @Test
  void shouldProduceUncustomizedRequestWhenNoCustomizationsConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository,
            Map.of(REGISTRATION_ID, new OidcConfiguration()));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result).isNotNull();
    assertThat(result.getAdditionalParameters()).doesNotContainKey("resource");
    // Spring's default still injects nonce, response_type, etc. — we only assert nothing
    // host-defined leaked in.
  }

  @Test
  void shouldAddEveryAdditionalParameterWhenConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(Map.of("prompt", "consent", "audience", "api"));
    oidc.setAuthorizeRequest(authorize);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("prompt", "consent")
        .containsEntry("audience", "api");
  }

  @Test
  void shouldAddResourceParameterWhenConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    oidc.setResource(List.of("https://api.example.com"));

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("resource", List.of("https://api.example.com"));
  }

  @Test
  void shouldAddBothAdditionalParametersAndResourceWhenBothConfigured() {
    when(clientRegistrationRepository.findByRegistrationId(REGISTRATION_ID))
        .thenReturn(clientRegistration);
    final var oidc = new OidcConfiguration();
    oidc.setResource(List.of("https://api.example.com"));
    final var authorize = new AuthorizeRequestConfiguration();
    authorize.setAdditionalParameters(Map.of("prompt", "consent"));
    oidc.setAuthorizeRequest(authorize);

    final var resolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, Map.of(REGISTRATION_ID, oidc));
    final var request = new MockHttpServletRequest("GET", AUTHORIZATION_REQUEST_URI);

    final var result = resolver.resolve(request);

    assertThat(result.getAdditionalParameters())
        .containsEntry("prompt", "consent")
        .containsEntry("resource", List.of("https://api.example.com"));
  }
}
```

- [ ] **Step 2: Run the test file and confirm compile failure**

```
mvn -pl spring-boot-starter test -Dtest=CamundaOidcAuthorizationRequestResolverTest
```

Expected: compile failure — `CamundaOidcAuthorizationRequestResolver` does not exist.

- [ ] **Step 3: Implement the resolver class**

Create `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolver.java` with the following exact contents:

```java
/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.AuthorizeRequestConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * CSL default {@link OAuth2AuthorizationRequestResolver} for the OIDC webapp chain. Lifts OC's
 * {@code ClientAwareOAuth2AuthorizationRequestResolver}: per-registrationId, wraps Spring
 * Security's {@link DefaultOAuth2AuthorizationRequestResolver} with a customizer that injects
 * {@code additional_parameters} and the {@code resource} (RFC 8707) parameter from {@link
 * OidcConfiguration} into the outgoing {@link OAuth2AuthorizationRequest}.
 *
 * <p>Expected request path: {@code /oauth2/authorization/{registrationId}}. Per-registrationId
 * delegating resolvers are cached in a {@link ConcurrentHashMap} so the customizer is built once
 * per id.
 *
 * <p>The {@code sourcesByRegistrationId} map MUST be built from the same flat-plus-providers merge
 * that produced the {@link ClientRegistrationRepository} so registrationIds stay aligned.
 */
public final class CamundaOidcAuthorizationRequestResolver
    implements OAuth2AuthorizationRequestResolver {

  private static final String ERROR_INVALID_CLIENT_REGISTRATION_ID =
      "Invalid Client Registration with ID '%s'";
  private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
  private static final String REGISTRATION_ID = "registrationId";

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final Map<String, OidcConfiguration> sourcesByRegistrationId;
  private final Map<String, OAuth2AuthorizationRequestResolver> resolvers;
  private final RequestMatcher authorizationRequestMatcher;

  public CamundaOidcAuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final Map<String, OidcConfiguration> sourcesByRegistrationId) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.sourcesByRegistrationId = Map.copyOf(sourcesByRegistrationId);
    resolvers = new ConcurrentHashMap<>();
    authorizationRequestMatcher =
        PathPatternRequestMatcher.withDefaults()
            .matcher("%s/{%s}".formatted(AUTHORIZATION_REQUEST_BASE_URI, REGISTRATION_ID));
  }

  @Override
  public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
    final var registrationId = resolveRegistrationId(request);
    return resolveInternal(registrationId, r -> r.resolve(request));
  }

  @Override
  public OAuth2AuthorizationRequest resolve(
      final HttpServletRequest request, final String registrationId) {
    return resolveInternal(registrationId, r -> r.resolve(request, registrationId));
  }

  private OAuth2AuthorizationRequest resolveInternal(
      final String registrationId,
      final Function<OAuth2AuthorizationRequestResolver, OAuth2AuthorizationRequest>
          requestSupplier) {
    if (registrationId == null || registrationId.isBlank()) {
      return null;
    }
    ensureClientRegistrationExists(registrationId);
    return Optional.of(getOrCreateResolver(registrationId))
        .map(requestSupplier)
        .orElse(null);
  }

  private void ensureClientRegistrationExists(final String registrationId) {
    final var registration = clientRegistrationRepository.findByRegistrationId(registrationId);
    if (registration == null) {
      throw new IllegalArgumentException(
          ERROR_INVALID_CLIENT_REGISTRATION_ID.formatted(registrationId));
    }
  }

  private OAuth2AuthorizationRequestResolver getOrCreateResolver(final String registrationId) {
    return resolvers.computeIfAbsent(registrationId, this::createResolver);
  }

  private OAuth2AuthorizationRequestResolver createResolver(final String registrationId) {
    final var resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, AUTHORIZATION_REQUEST_BASE_URI);
    final var source = sourcesByRegistrationId.get(registrationId);
    if (source != null) {
      resolver.setAuthorizationRequestCustomizer(createCustomizer(source));
    }
    return resolver;
  }

  private static Consumer<Builder> createCustomizer(final OidcConfiguration source) {
    return builder -> {
      final AuthorizeRequestConfiguration authorize = source.getAuthorizeRequest();
      final Map<String, Object> additionalParameters =
          authorize != null ? authorize.getAdditionalParameters() : null;
      if (additionalParameters != null && !additionalParameters.isEmpty()) {
        builder.additionalParameters(additionalParameters);
      }
      final var resource = source.getResource();
      if (resource != null && !resource.isEmpty()) {
        builder.additionalParameters(Map.of(OAuth2ParameterNames.RESOURCE, resource));
      }
    };
  }

  private String resolveRegistrationId(final HttpServletRequest request) {
    if (!authorizationRequestMatcher.matches(request)) {
      return null;
    }
    return authorizationRequestMatcher.matcher(request).getVariables().get(REGISTRATION_ID);
  }
}
```

- [ ] **Step 4: Run the unit tests and confirm they pass**

```
mvn -pl spring-boot-starter test -Dtest=CamundaOidcAuthorizationRequestResolverTest
```

Expected: `BUILD SUCCESS` — all 7 tests pass.

- [ ] **Step 5: Commit**

```
git add spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolver.java spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/CamundaOidcAuthorizationRequestResolverTest.java
git commit -m "$(cat <<'EOF'
feat(spring-boot-starter): add CamundaOidcAuthorizationRequestResolver

Lifts OC's ClientAwareOAuth2AuthorizationRequestResolver into CSL. The
resolver wraps Spring Security's DefaultOAuth2AuthorizationRequestResolver
per registrationId and injects 'additional_parameters' plus the RFC 8707
'resource' parameter from OidcConfiguration into the outgoing
OAuth2AuthorizationRequest. Per-registration delegating resolvers are
cached so the customizer is built once per id, matching OC's behaviour.

Refs #232.
EOF
)"
```

---

## Task 3: Wire the `@Bean` and add context tests

**Files:**
- Modify: `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java`
- Modify: `spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/OidcBeansConfigurationTest.java`

- [ ] **Step 1: Write the failing context tests**

Open `spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/OidcBeansConfigurationTest.java`. Add the following imports next to the existing ones (alphabetical with the others in the `org.springframework.security.oauth2.client.web` block):

```java
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
```

Also add (for the host-bean test):

```java
import io.camunda.security.spring.oidc.CamundaOidcAuthorizationRequestResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
```

Add these two new `@Test` methods immediately after the existing `hostRegisteredLogoutSuccessHandlerSuppressesTheDefault` method:

```java
  @Test
  void defaultCamundaOidcAuthorizationRequestResolverIsRegisteredWhenNoHostBeanPresent() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
          assertThat(ctx)
              .getBean(OAuth2AuthorizationRequestResolver.class)
              .isInstanceOf(CamundaOidcAuthorizationRequestResolver.class);
        });
  }

  @Test
  void hostRegisteredAuthorizationRequestResolverSuppressesTheDefault() {
    runner
        .withUserConfiguration(HostAuthorizationRequestResolver.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
              assertThat(ctx)
                  .getBean(OAuth2AuthorizationRequestResolver.class)
                  .isInstanceOf(HostAuthorizationRequestResolver.NoOpResolver.class);
            });
  }
```

Then add a new static inner `@Configuration` class at the bottom of the file (after `HostLogoutSuccessHandler`):

```java
  @Configuration
  static class HostAuthorizationRequestResolver {

    @Bean
    OAuth2AuthorizationRequestResolver hostAuthorizationRequestResolver() {
      return new NoOpResolver();
    }

    static final class NoOpResolver implements OAuth2AuthorizationRequestResolver {
      @Override
      public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
        return null;
      }

      @Override
      public OAuth2AuthorizationRequest resolve(
          final HttpServletRequest request, final String clientRegistrationId) {
        return null;
      }
    }
  }
```

- [ ] **Step 2: Run the new tests and confirm they fail**

```
mvn -pl spring-boot-starter test -Dtest='OidcBeansConfigurationTest#defaultCamundaOidcAuthorizationRequestResolverIsRegisteredWhenNoHostBeanPresent+hostRegisteredAuthorizationRequestResolverSuppressesTheDefault'
```

Expected: both new tests fail — `OidcBeansConfiguration` does not yet expose an `OAuth2AuthorizationRequestResolver` bean.

- [ ] **Step 3: Register the `@Bean` in `OidcBeansConfiguration`**

Open `spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java`.

Add these two imports next to the existing ones (alphabetical order in their respective blocks):

```java
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
```

(`DefaultOAuth2AuthorizationRequestResolver` is not used in `OidcBeansConfiguration` directly — drop it if your IDE flags it as unused. The resolver class uses it.)

Insert the new `@Bean` method directly above `authorizedClientRepository` (currently at line 351):

```java
  /**
   * Default {@link OAuth2AuthorizationRequestResolver} for the OIDC webapp chain. Injects
   * per-provider {@code additional_parameters} and the RFC 8707 {@code resource} parameter from
   * {@link OidcConfiguration} into the outgoing {@link
   * org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest}. Backs off via
   * {@link ConditionalOnMissingBean} when the host registers its own resolver — e.g. OC's existing
   * {@code ClientAwareOAuth2AuthorizationRequestResolver}, until the monorepo cleanup PR removes it.
   *
   * <p>The {@link OidcConfiguration} sources map is built from the same flat-plus-providers merge as
   * {@link #clientRegistrationRepository(CamundaSecurityLibraryProperties)} so registrationIds stay
   * aligned.
   */
  @Bean
  @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)
  public OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver(
      final ClientRegistrationRepository clientRegistrationRepository,
      final CamundaSecurityLibraryProperties properties) {
    return new CamundaOidcAuthorizationRequestResolver(
        clientRegistrationRepository, buildOidcSources(properties.getAuthentication()));
  }
```

- [ ] **Step 4: Run the new tests and confirm they pass**

```
mvn -pl spring-boot-starter test -Dtest='OidcBeansConfigurationTest#defaultCamundaOidcAuthorizationRequestResolverIsRegisteredWhenNoHostBeanPresent+hostRegisteredAuthorizationRequestResolverSuppressesTheDefault'
```

Expected: `BUILD SUCCESS` — both new tests pass.

- [ ] **Step 5: Run the full `OidcBeansConfigurationTest` to confirm no regression**

```
mvn -pl spring-boot-starter test -Dtest=OidcBeansConfigurationTest
```

Expected: `BUILD SUCCESS` — all four tests pass (the two original logout-handler tests plus the two new resolver tests).

- [ ] **Step 6: Commit**

```
git add spring-boot-starter/src/main/java/io/camunda/security/spring/oidc/OidcBeansConfiguration.java spring-boot-starter/src/test/java/io/camunda/security/spring/oidc/OidcBeansConfigurationTest.java
git commit -m "$(cat <<'EOF'
feat(spring-boot-starter): expose CamundaOidcAuthorizationRequestResolver as default bean

OidcBeansConfiguration now ships a CamundaOidcAuthorizationRequestResolver
under @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class).
Hosts that already register their own resolver (notably OC today) keep
winning; once the monorepo deletes OC's resolver, the CSL default takes
over without any host-side config change.

The bean reads its OidcConfiguration sources from the same
flat-plus-providers merge that builds the ClientRegistrationRepository, via
the new shared buildOidcSources helper, so registrationIds stay aligned.

Closes #232 (with the existing webapp hook test still passing — see the
follow-up commit that updates the now-stale 'no resolver bean' assertion).
EOF
)"
```

---

## Task 4: Update the existing webapp-chain hook test

**Files:**
- Modify: `spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappAuthorizationRequestResolverHookTest.java` (lines 74–85, the `chainBuildsWithoutHostResolver` method)

After Task 3, `OidcBeansConfiguration` registers a default resolver. The existing test that asserts `doesNotHaveBean(OAuth2AuthorizationRequestResolver.class)` is now stale — flip it.

- [ ] **Step 1: Confirm the test now fails**

```
mvn -pl spring-boot-starter test -Dtest='OidcWebappAuthorizationRequestResolverHookTest#chainBuildsWithoutHostResolver'
```

Expected: `chainBuildsWithoutHostResolver` fails — the context now contains a `CamundaOidcAuthorizationRequestResolver` bean, so `doesNotHaveBean(OAuth2AuthorizationRequestResolver.class)` is false.

- [ ] **Step 2: Update the test to assert CSL's default is wired**

Open the file. Add this import next to the other `io.camunda.security.spring.oidc` import (line 16):

```java
import io.camunda.security.spring.oidc.CamundaOidcAuthorizationRequestResolver;
```

Replace the `chainBuildsWithoutHostResolver` method (lines 74–85) with:

```java
  @Test
  void chainBuildsWithCslDefaultResolverWhenNoHostResolverPresent() {
    // CSL's OidcBeansConfiguration now ships a default CamundaOidcAuthorizationRequestResolver under
    // @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class). Without a host bean of
    // that type, the chain consumes CSL's default through the same SPI hook this test class
    // otherwise verifies host beans flow through. Asserting on the instance type (rather than just
    // bean presence) confirms the wiring is the lifted resolver, not a stray Spring default.
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();
          assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
          assertThat(ctx.getBean(OAuth2AuthorizationRequestResolver.class))
              .isInstanceOf(CamundaOidcAuthorizationRequestResolver.class);

          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          assertThat(chain).isInstanceOf(DefaultSecurityFilterChain.class);
          final var redirectFilter =
              filtersOf(chain).stream()
                  .filter(OAuth2AuthorizationRequestRedirectFilter.class::isInstance)
                  .map(OAuth2AuthorizationRequestRedirectFilter.class::cast)
                  .findFirst()
                  .orElseThrow(
                      () ->
                          new AssertionError(
                              "OAuth2AuthorizationRequestRedirectFilter not present in chain"));
          final var field =
              OAuth2AuthorizationRequestRedirectFilter.class.getDeclaredField(
                  "authorizationRequestResolver");
          field.setAccessible(true);
          assertThat(field.get(redirectFilter))
              .isInstanceOf(CamundaOidcAuthorizationRequestResolver.class);
        });
  }
```

- [ ] **Step 3: Run the full file to confirm all four tests pass**

```
mvn -pl spring-boot-starter test -Dtest=OidcWebappAuthorizationRequestResolverHookTest
```

Expected: `BUILD SUCCESS` — all four tests pass (`chainBuildsWithCslDefaultResolverWhenNoHostResolverPresent`, `hostResolverBeanIsWiredIntoTheAuthorizationRequestRedirectFilter`, `anonymousLoginUrlRequestIsPermittedAndDoesNotLoopBackToLogin`, `anonymousLogoutUrlRequestIsPermittedAndDoesNotRedirectToLogin`).

- [ ] **Step 4: Commit**

```
git add spring-boot-starter/src/test/java/io/camunda/security/spring/security/OidcWebappAuthorizationRequestResolverHookTest.java
git commit -m "$(cat <<'EOF'
test(spring-boot-starter): assert CSL's default resolver is wired into the OIDC webapp chain

Now that OidcBeansConfiguration ships a CamundaOidcAuthorizationRequestResolver
by default, flip the previous 'no resolver bean' assertion to assert that
the chain's OAuth2AuthorizationRequestRedirectFilter holds an instance of
the CSL resolver. The host-resolver-wins assertion in the sibling test is
unchanged — @ConditionalOnMissingBean still backs CSL off when a host bean
is present.
EOF
)"
```

---

## Task 5: Adopter guide

**Files:**
- Modify: `docs/adopters/security-filter-chains.md` — insert a new sub-section between line 280 (end of "Disabling the UserInfo fetch") and line 282 (start of "OIDC groups claim extraction")

- [ ] **Step 1: Insert the new sub-section**

Open `docs/adopters/security-filter-chains.md`. After the existing line 280 (`A host-supplied OidcUserService bean still takes precedence…`) and before line 282 (`### OIDC groups claim extraction`), insert:

```markdown
### Customising the authorisation request (`resource`, `additional_parameters`)

CSL ships a default `OAuth2AuthorizationRequestResolver` (`CamundaOidcAuthorizationRequestResolver`) from `OidcBeansConfiguration`. It wraps Spring Security's `DefaultOAuth2AuthorizationRequestResolver` per registration and injects two `OidcConfiguration` properties into the outgoing OAuth2 authorisation request. Hosts that need different customizer logic register their own `OAuth2AuthorizationRequestResolver` bean; CSL backs off via `@ConditionalOnMissingBean`.

#### `resource` (RFC 8707)

When `resource` is set on a provider, every entry in the list is added as a `resource` query parameter on the IdP authorisation URL. Use this when the IdP requires an explicit audience for the issued access token.

#### `authorize-request.additional-parameters`

Arbitrary key/value pairs that are appended verbatim to the authorisation request. Useful for IdP-specific extensions such as `prompt`, `audience`, or vendor-specific switches. Values are passed through unchanged — the library does not interpret them.

#### Worked example

Both knobs are valid on the flat block and on any `providers.oidc.<id>.*` entry:

```yaml
camunda:
  security:
    authentication:
      method: oidc
      oidc:
        issuer-uri: https://idp.example.com
        client-id: camunda
        client-secret: ${OIDC_SECRET}
        redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        resource:
          - https://api.example.com
        authorize-request:
          additional-parameters:
            prompt: consent
            audience: https://api.example.com
      providers:
        oidc:
          partner:
            issuer-uri: https://partner.example.com
            client-id: camunda-partner
            client-secret: ${PARTNER_SECRET}
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            resource:
              - https://partner-api.example.com
```

If you need behaviour the customizer does not cover (e.g. PKCE forcing, claims request, dynamic per-request parameters), register your own `OAuth2AuthorizationRequestResolver` bean — CSL's default will back off and the OIDC webapp chain will pick yours up automatically.

```

- [ ] **Step 2: Commit**

```
git add docs/adopters/security-filter-chains.md
git commit -m "docs(adopters): document resource and additional_parameters customisation"
```

---

## Task 6: Final verification

- [ ] **Step 1: Full module verify**

```
mvn -pl spring-boot-starter verify
```

Expected: `BUILD SUCCESS`.

- [ ] **Step 2: Full project verify (catches any cross-module fallout)**

```
mvn verify
```

Expected: `BUILD SUCCESS`. No test failures anywhere.

- [ ] **Step 3: Confirm the change log against the issue acceptance criteria**

Walk through each checkbox in [issue #232 Acceptance Criteria](https://github.com/camunda/camunda-security-library/issues/232) and confirm:

- [x] CSL exposes `OAuth2AuthorizationRequestResolver` from `OidcBeansConfiguration` under `@ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)` → Task 3 Step 3
- [x] Configured `resource` lands on the request as `resource` param → covered by `shouldAddResourceParameterWhenConfigured` (Task 2)
- [x] Configured `authorize_request.additional_parameters` lands on the request → covered by `shouldAddEveryAdditionalParameterWhenConfigured` (Task 2)
- [x] When neither set, no behavioural change vs Spring's default → covered by `shouldProduceUncustomizedRequestWhenNoCustomizationsConfigured` (Task 2)
- [x] Host-registered bean takes precedence → covered by `hostRegisteredAuthorizationRequestResolverSuppressesTheDefault` (Task 3)
- [x] Unit tests cover all four states + invalid-registrationId → Task 2
- [x] Adopter guide documents both properties with a worked example → Task 5
- [x] `mvn verify` passes → this task

- [ ] **Step 4: Open the PR (optional — let the user decide)**

Do **not** push or open a PR automatically. Stop and report. The user will review the commits and decide when to open the PR.

---

## Self-review notes

- Type consistency: the resolver constructor signature `(ClientRegistrationRepository, Map<String, OidcConfiguration>)` is used identically in Task 2 (unit tests + impl) and Task 3 (the `@Bean` method).
- Helper method name `buildOidcSources` is used identically in Task 1 (extraction + call from `clientRegistrationRepository`) and Task 3 (call from the new resolver `@Bean`).
- The customizer treats `getAuthorizeRequest()` defensively (null check) because `OidcConfiguration` initialises it to a non-null default in the constructor but the setter accepts null — keeping the resolver tolerant of either shape.
- No placeholders: every code block is complete and copy-pasteable.
- Spec coverage: every section of the spec (resolver class, wiring, three test suites, adopter guide, verification) maps to a numbered task.
