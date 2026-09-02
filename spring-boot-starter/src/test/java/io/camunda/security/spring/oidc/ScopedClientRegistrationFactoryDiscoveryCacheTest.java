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

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Tests for {@link ScopedClientRegistrationFactory}'s per-issuer discovery cache. Split out from
 * {@link ScopedClientRegistrationFactoryTest}, which covers the provider-map and redirect-uri logic
 * that needs no network: every test here resolves an {@code issuer-uri} against a local {@link
 * OidcTestServer}, and most assert on how many times that server was asked for its document.
 */
class ScopedClientRegistrationFactoryDiscoveryCacheTest {

  private static final String DISCOVERY_TEMPLATE =
      """
      {
        "issuer": "%1$s",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  /** Discovery document that advertises an {@code end_session_endpoint}, as real IdPs do. */
  private static final String DISCOVERY_TEMPLATE_WITH_END_SESSION =
      """
      {
        "issuer": "%1$s",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "end_session_endpoint": "%1$s/logout",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  /** Discovery document missing {@code authorization_endpoint} — the #233 shape. */
  private static final String DISCOVERY_TEMPLATE_NO_AUTHORIZATION_ENDPOINT =
      """
      {
        "issuer": "%1$s",
        "token_endpoint": "%1$s/token",
        "jwks_uri": "%1$s/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
      }
      """;

  /** An RFC 8414 authorization-server document with no {@code jwks_uri}. */
  private static final String RFC8414_TEMPLATE_NO_JWKS =
      """
      {
        "issuer": "%1$s",
        "authorization_endpoint": "%1$s/auth",
        "token_endpoint": "%1$s/token",
        "response_types_supported": ["code"]
      }
      """;

  private ScopedClientRegistrationFactory factory;
  private OidcTestServer oidcServer;
  private OidcTestServer otherOidcServer;

  @BeforeEach
  void setUp() {
    factory = new ScopedClientRegistrationFactory();
  }

  @AfterEach
  void tearDown() {
    if (oidcServer != null) {
      oidcServer.close();
      oidcServer = null;
    }
    if (otherOidcServer != null) {
      otherOidcServer.close();
      otherOidcServer = null;
    }
  }

  // ---------------------------------------------------------------------------
  // Fetch counts, keying and scope
  // ---------------------------------------------------------------------------

  @Test
  void shouldFetchDiscoveryOnceForRegistrationsSharingAnIssuerInOneCall() throws Exception {
    // All three resolve the same issuer, so the document is fetched once and re-derived per
    // registration.
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var providers =
        Map.of(
            "idp1", issuerBased("client-1", oidcServer.issuerUri()),
            "idp2", issuerBased("client-2", oidcServer.issuerUri()),
            "idp3", issuerBased("client-3", oidcServer.issuerUri()));

    assertThat(factory.createFromProviderMap(providers)).hasSize(3);
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldFetchDiscoveryOnceAcrossSeparateCallsOnTheSameFactory() throws Exception {
    // The case that matters in production: the factory is a singleton injected into several
    // consumers, so deduplicating only within one call would deliver nothing.
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();

    factory.createFromProviderMap(Map.of("idp1", issuerBased("client-1", issuer)));
    factory.createFromProviderMap(Map.of("idp2", issuerBased("client-2", issuer)));
    factory.createFromProviderMap(Map.of("idp3", issuerBased("client-3", issuer)));

    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldFetchDiscoveryPerIssuerWhenIssuersDiffer() throws Exception {
    // given two providers on two different issuers
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    otherOidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-1", issuerBased("client-1", oidcServer.issuerUri()));
    providers.put("idp-2", issuerBased("client-2", otherOidcServer.issuerUri()));

    // when
    final var byId = registrationsById(providers);

    // then each issuer was resolved on its own, and registration 2 points at its own IdP — an
    // over-coarse key would silently give it the first issuer's endpoints
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
    assertThat(otherOidcServer.discoveryRequestCount()).isEqualTo(1);
    assertThat(byId.get("idp-2").getProviderDetails().getTokenUri())
        .isEqualTo(otherOidcServer.issuerUri() + "/token");
  }

  @Test
  void shouldNotServeCachedDocumentUnderATrailingSlashVariantOfTheIssuer() throws Exception {
    // given one provider that has already populated the cache for an issuer
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();
    factory.createFromProviderMap(Map.of("idp-1", issuerBased("client-1", issuer)));
    final var countAfterFirst = oidcServer.discoveryRequestCount();

    // when a second provider configures the same IdP with a trailing slash
    final var slashed = Map.of("idp-2", issuerBased("client-2", issuer + "/"));

    // then it resolves on its own instead of being served the cached document. The count is the
    // real guard: a normalized key would neither re-fetch nor fail, because Spring takes the
    // issuer from the document itself. The failure is only asserted as a RuntimeException — which
    // exception depends on Spring's probe order, not on this cache.
    assertThatThrownBy(() -> factory.createFromProviderMap(slashed))
        .isInstanceOf(RuntimeException.class);
    assertThat(oidcServer.discoveryRequestCount()).isGreaterThan(countAfterFirst);
  }

  @Test
  void shouldNotShareTheDiscoveryCacheBetweenFactoryInstances() throws Exception {
    // given the same provider map built by two separate factories
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var providers = Map.of("idp-1", issuerBased("client-1", oidcServer.issuerUri()));

    // when
    factory.createFromProviderMap(providers);
    new ScopedClientRegistrationFactory().createFromProviderMap(providers);

    // then each fetched for itself: the cache is per instance, never static. Surefire runs all 28
    // oidc test classes in one JVM and OidcTestServer binds ephemeral ports, so a static cache
    // could serve a recycled port a dead server's document.
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(2);
  }

  @Test
  void shouldNotFetchDiscoveryForProvidersWithoutIssuerUri() throws Exception {
    // given a reachable IdP but two providers configured entirely with explicit endpoints
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-1", explicitEndpoints("client-1", oidcServer.issuerUri()));
    providers.put("idp-2", explicitEndpoints("client-2", oidcServer.issuerUri()));

    // when
    assertThat(factory.createFromProviderMap(providers)).hasSize(2);

    // then no issuer-uri means no fetch at all
    assertThat(oidcServer.discoveryRequestCount()).isZero();
  }

  // ---------------------------------------------------------------------------
  // Per-registration isolation
  // ---------------------------------------------------------------------------

  @ParameterizedTest(name = "reversed={0}")
  @ValueSource(booleans = {false, true})
  void shouldKeepPerRegistrationFieldsIndependentWhenSharingAnIssuer(final boolean reversed)
      throws Exception {
    // given two providers on one issuer, differing in every field a registration carries itself
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();

    // when built in both insertion orders — the map order decides which registration fetches and
    // which is re-derived from the cached document
    final var byId =
        registrationsById(
            bothOrders(reversed, distinctProvider("a", issuer), distinctProvider("b", issuer)));

    // then each registration kept its own credentials, scopes and redirect-uri
    assertThat(byId).containsOnlyKeys("idp-a", "idp-b");
    assertOwnFields(byId.get("idp-a"), "a");
    assertOwnFields(byId.get("idp-b"), "b");
    // and it held on the cached path, not because both registrations re-discovered
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @ParameterizedTest(name = "reversed={0}")
  @ValueSource(booleans = {false, true})
  void shouldValidateEachRegistrationAgainstItsOwnAudiencesWhenSharingAnIssuer(
      final boolean reversed) throws Exception {
    // given two providers on one issuer with disjoint audiences
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();
    final var providers =
        bothOrders(
            reversed,
            audienceProvider("a", issuer, "aud-a"),
            audienceProvider("b", issuer, "aud-b"));
    final var byId = registrationsById(providers);

    // when validators are composed the way the decoder factory composes them
    final var validators = new TokenValidatorFactory(providers, Duration.ofSeconds(60), List.of());
    final var tokenForA = jwtWithAudience(issuer, "aud-a");

    // then B rejects a token minted for A. Asserted at the validator, not the metadata map: a
    // shared metadata map is an auth bypass, because audiences are authoritative by presence.
    assertThat(validators.createTokenValidator(byId.get("idp-a")).validate(tokenForA).hasErrors())
        .isFalse();
    assertThat(validators.createTokenValidator(byId.get("idp-b")).validate(tokenForA).hasErrors())
        .isTrue();
  }

  @ParameterizedTest(name = "reversed={0}")
  @ValueSource(booleans = {false, true})
  void shouldApplyJwkSetUriOverrideToOnlyTheRegistrationThatConfiguresIt(final boolean reversed)
      throws Exception {
    // given one provider overriding jwk-set-uri and one taking the discovered value
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();
    final var overriding =
        OidcConfiguration.builder()
            .clientId("a")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(issuer)
            .jwkSetUri("https://override.example.com/jwks")
            .build();

    // when built in both insertion orders: the factory sets jwk-set-uri only when configured, so
    // on a shared builder it would leak onto whichever registration is built second — a single
    // order would pass
    final var byId = registrationsById(bothOrders(reversed, overriding, issuerBased("b", issuer)));

    // then the override stays local to its own registration in either order
    assertThat(byId.get("idp-a").getProviderDetails().getJwkSetUri())
        .isEqualTo("https://override.example.com/jwks");
    assertThat(byId.get("idp-b").getProviderDetails().getJwkSetUri()).isEqualTo(issuer + "/jwks");
    // and one of the two came off the cached document — without this the test would also pass with
    // the cache bypassed, which is not what it claims to cover
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @ParameterizedTest(name = "reversed={0}")
  @ValueSource(booleans = {false, true})
  void shouldKeepEndSessionEndpointPerRegistrationWhenSharingAnIssuer(final boolean reversed)
      throws Exception {
    // given an IdP advertising an end_session_endpoint, and two providers on it: one overriding
    // that endpoint, one taking the discovered value
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE_WITH_END_SESSION);
    final var issuer = oidcServer.issuerUri();
    final var overriding =
        OidcConfiguration.builder()
            .clientId("a")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(issuer)
            .endSessionEndpointUri("https://explicit.example.com/logout")
            .build();

    // when
    final var byId = registrationsById(bothOrders(reversed, overriding, issuerBased("b", issuer)));

    // then neither registration sees the other's logout endpoint. This rides the same merged
    // metadata map as audiences, so it fails the same way if that map is ever shared.
    assertThat(endSessionEndpointOf(byId.get("idp-a")))
        .isEqualTo("https://explicit.example.com/logout");
    assertThat(endSessionEndpointOf(byId.get("idp-b"))).isEqualTo(issuer + "/logout");
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldCarryUserNameAttributeOnRegistrationsBuiltFromTheCachedDocument() throws Exception {
    // given two providers on one issuer, so only the first resolves it over HTTP
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    final var issuer = oidcServer.issuerUri();
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-a", issuerBased("a", issuer));
    providers.put("idp-b", issuerBased("b", issuer));

    // when
    final var registrations = factory.createFromProviderMap(providers);

    // then discovery-derived fields nobody asserts on elsewhere survive the cached path too — the
    // silent-field class of regression behind #621
    assertThat(registrations)
        .hasSize(2)
        .allSatisfy(
            reg -> {
              assertThat(reg.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName())
                  .isEqualTo("sub");
              assertThat(reg.getClientName()).isEqualTo(issuer);
            });
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldPreserveDiscoveredEndSessionEndpointWhenStashingAudiences() throws Exception {
    // given a discovery document that advertises an end_session_endpoint (as real IdPs do) but no
    // explicitly-configured end-session URI on the OidcConfiguration
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE_WITH_END_SESSION);
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(oidcServer.issuerUri())
            .audiences(Set.of("scoped-aud"))
            .build();

    // when discovery populates the registration's metadata, then we merge our additions on top
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then the discovered end_session_endpoint survives alongside the stashed audiences
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata.get("end_session_endpoint")).isEqualTo(oidcServer.issuerUri() + "/logout");
    assertThat(metadata.get(TokenValidatorFactory.AUDIENCES_METADATA_KEY))
        .asInstanceOf(InstanceOfAssertFactories.collection(String.class))
        .containsExactly("scoped-aud");
  }

  @Test
  void shouldOverrideDiscoveredEndSessionEndpointWithExplicitConfig() throws Exception {
    // given a discovery document advertising an end_session_endpoint, and an explicitly-configured
    // end-session URI
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE_WITH_END_SESSION);
    final var oidc =
        OidcConfiguration.builder()
            .clientId("my-client")
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .issuerUri(oidcServer.issuerUri())
            .endSessionEndpointUri("https://explicit.example.com/logout")
            .build();

    // when
    final var registrations = factory.createFromProviderMap(Map.of("myid", oidc));

    // then explicit config wins over the discovered value
    final var metadata = registrations.get(0).getProviderDetails().getConfigurationMetadata();
    assertThat(metadata.get("end_session_endpoint"))
        .isEqualTo("https://explicit.example.com/logout");
  }

  // ---------------------------------------------------------------------------
  // Incomplete documents and failures
  // ---------------------------------------------------------------------------

  @Test
  void shouldBuildEveryRegistrationWhenDiscoveryOmitsAuthorizationEndpoint() throws Exception {
    // given an IdP whose discovery document omits authorization_endpoint, and two providers
    // plugging the gap explicitly — #233, and why the overrides must run before build() asserts
    // authorizationUri is present
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE_NO_AUTHORIZATION_ENDPOINT);
    final var issuer = oidcServer.issuerUri();
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-1", authorizationOverriding("client-1", issuer));
    providers.put("idp-2", authorizationOverriding("client-2", issuer));

    // when
    final var byId = registrationsById(providers);

    // then the registration derived from the cached document builds too, keeps its own override
    // rather than the first registration's, and the document was still worth caching
    assertThat(byId).containsOnlyKeys("idp-1", "idp-2");
    assertThat(byId.get("idp-1").getProviderDetails().getAuthorizationUri())
        .isEqualTo("https://explicit.example.com/client-1/auth");
    assertThat(byId.get("idp-2").getProviderDetails().getAuthorizationUri())
        .isEqualTo("https://explicit.example.com/client-2/auth");
    assertThat(oidcServer.discoveryRequestCount()).isEqualTo(1);
  }

  @Test
  void shouldBuildEveryRegistrationWhenTheDiscoveredDocumentHasNoJwksUri() throws Exception {
    // given an IdP resolved through Spring's RFC 8414 fallback, the only route that accepts a
    // document with no jwks_uri, and two providers supplying one explicitly — the #233 pattern
    oidcServer = OidcTestServer.startRfc8414Discovery("/realms/main", RFC8414_TEMPLATE_NO_JWKS);
    final var issuer = oidcServer.issuerUri() + "/realms/main";
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-1", jwksOverriding("client-1", issuer));
    providers.put("idp-2", jwksOverriding("client-2", issuer));

    // when
    final var byId = registrationsById(providers);

    // then registration 2 builds as well: fromOidcConfiguration dereferences the document's
    // jwks_uri unguarded, so re-deriving from the cached document cannot be the only path
    assertThat(byId).containsOnlyKeys("idp-1", "idp-2");
    assertThat(byId.get("idp-1").getProviderDetails().getJwkSetUri())
        .isEqualTo("https://override.example.com/client-1/jwks");
    assertThat(byId.get("idp-2").getProviderDetails().getJwkSetUri())
        .isEqualTo("https://override.example.com/client-2/jwks");
  }

  @Test
  void shouldNotCacheAFailedDiscoveryAttempt() throws Exception {
    // given an IdP that fails the first discovery request and serves normally afterwards
    oidcServer = OidcTestServer.startDiscovery(DISCOVERY_TEMPLATE);
    oidcServer.failNextDiscoveryRequests(1);
    final var providers = Map.of("idp-1", issuerBased("client-1", oidcServer.issuerUri()));

    // when the first attempt fails (a 5xx is not HttpClientErrorException, so Spring wraps it
    // rather than probing the RFC 8414 fallbacks)
    assertThatThrownBy(() -> factory.createFromProviderMap(providers))
        .isInstanceOf(IllegalArgumentException.class);
    final var countAfterFailure = oidcServer.discoveryRequestCount();

    // then a later build re-fetches and succeeds. The count is relative because the failed
    // attempt's probe count is beside the point. Caching a failure would poison the issuer for the
    // process lifetime, and ScopedWebappSecurityChainBuilder builds chains long after startup.
    assertThat(factory.createFromProviderMap(providers)).hasSize(1);
    assertThat(oidcServer.discoveryRequestCount()).isGreaterThan(countAfterFailure);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /** Creates an {@link OidcConfiguration} that resolves its endpoints through issuer discovery. */
  private static OidcConfiguration issuerBased(final String clientId, final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .build();
  }

  /** Creates an {@link OidcConfiguration} with explicit endpoints — no issuer-uri discovery. */
  private static OidcConfiguration explicitEndpoints(final String clientId, final String base) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri(base + "/auth")
        .tokenUri(base + "/token")
        .jwkSetUri(base + "/jwks")
        .build();
  }

  /**
   * Creates a discovery-based config whose per-registration fields are all derived from {@code
   * clientId}, so a leak between registrations surfaces as the other client's value.
   */
  private static OidcConfiguration distinctProvider(final String clientId, final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .clientSecret("secret-" + clientId)
        .scope(List.of("openid", "scope-" + clientId))
        .redirectUri("{baseUrl}/" + clientId + "/sso-callback")
        .issuerUri(issuerUri)
        .build();
  }

  /**
   * Creates a discovery-based config that plugs a missing authorization_endpoint explicitly. The
   * URL carries the client id, so a value leaking between registrations is visible.
   */
  private static OidcConfiguration authorizationOverriding(
      final String clientId, final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .authorizationUri("https://explicit.example.com/" + clientId + "/auth")
        .build();
  }

  /**
   * Creates a discovery-based config that plugs a missing jwks_uri with an explicit override. The
   * URL carries the client id, so a value leaking between registrations is visible.
   */
  private static OidcConfiguration jwksOverriding(final String clientId, final String issuerUri) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .jwkSetUri("https://override.example.com/" + clientId + "/jwks")
        .build();
  }

  /** Creates a discovery-based config with a single audience. */
  private static OidcConfiguration audienceProvider(
      final String clientId, final String issuerUri, final String audience) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(issuerUri)
        .audiences(Set.of(audience))
        .build();
  }

  /**
   * Builds a two-entry provider map keyed {@code idp-<clientId>}, inserting {@code b} first when
   * {@code reversed} — the order the factory builds in, which is what an order-sensitive bug needs.
   */
  private static Map<String, OidcConfiguration> bothOrders(
      final boolean reversed, final OidcConfiguration a, final OidcConfiguration b) {
    final var first = reversed ? b : a;
    final var second = reversed ? a : b;
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    providers.put("idp-" + first.getClientId(), first);
    providers.put("idp-" + second.getClientId(), second);
    return providers;
  }

  /** Indexes the built registrations by registrationId, so assertions are order-independent. */
  private Map<String, ClientRegistration> registrationsById(
      final Map<String, OidcConfiguration> providers) {
    return factory.createFromProviderMap(providers).stream()
        .collect(Collectors.toMap(ClientRegistration::getRegistrationId, reg -> reg));
  }

  private static void assertOwnFields(final ClientRegistration reg, final String clientId) {
    assertThat(reg.getClientId()).isEqualTo(clientId);
    assertThat(reg.getClientSecret()).isEqualTo("secret-" + clientId);
    assertThat(reg.getScopes()).containsExactlyInAnyOrder("openid", "scope-" + clientId);
    assertThat(reg.getRedirectUri()).isEqualTo("{baseUrl}/" + clientId + "/sso-callback");
  }

  private static Object endSessionEndpointOf(final ClientRegistration reg) {
    return reg.getProviderDetails().getConfigurationMetadata().get("end_session_endpoint");
  }

  private static Jwt jwtWithAudience(final String issuer, final String audience) {
    return Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .issuer(issuer)
        .audience(List.of(audience))
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(60))
        .build();
  }
}
