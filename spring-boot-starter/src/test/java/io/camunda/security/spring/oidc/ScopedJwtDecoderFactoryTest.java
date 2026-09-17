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

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Unit tests for {@link ScopedJwtDecoderFactory}. Exercises the single-provider and multi-provider
 * paths by signing real JWTs against local JWKS servers — mirroring the crypto harness used by
 * {@link OidcBeansConfigurationMultiIssuerDecodeTest}.
 *
 * <p>Registrations are built with explicit endpoint URIs (no OIDC discovery network calls): the
 * {@link OidcConfiguration} supplies {@code jwkSetUri}, {@code authorizationUri}, and {@code
 * tokenUri} directly, plus the issuerUri so the {@link IssuerAwareJWSKeySelector} can route by
 * issuer. The local JWKS server also serves a minimal OIDC discovery document at {@code
 * /.well-known/openid-configuration} so that {@link
 * org.springframework.security.oauth2.client.registration.ClientRegistrations#fromIssuerLocation}
 * can complete without real external HTTP.
 */
final class ScopedJwtDecoderFactoryTest {

  private OidcTestServer serverA;
  private OidcTestServer serverB;

  @BeforeEach
  void setUp() {
    serverA = null;
    serverB = null;
  }

  /**
   * Creates a {@link ScopedJwtDecoderFactory} whose {@link TokenValidatorFactory} is seeded with
   * the given provider configurations so that issuer validators are active for the registered
   * issuers.
   */
  private static ScopedJwtDecoderFactory factoryFor(
      final Map<String, OidcConfiguration> providers) {
    final var jwsKeySelectorFactory = new JWSKeySelectorFactory();
    final var tokenValidatorFactory =
        new TokenValidatorFactory(providers, OidcConfiguration.DEFAULT_CLOCK_SKEW, List.of());
    final var decoderFactory =
        new OidcAccessTokenDecoderFactory(jwsKeySelectorFactory, tokenValidatorFactory);
    final var registrationFactory = new ScopedClientRegistrationFactory();
    return new ScopedJwtDecoderFactory(registrationFactory, decoderFactory);
  }

  @AfterEach
  void stopServers() {
    if (serverA != null) {
      serverA.stop();
    }
    if (serverB != null) {
      serverB.stop();
    }
  }

  // ---------------------------------------------------------------------------
  // Single provider
  // ---------------------------------------------------------------------------

  @Test
  void shouldDecodeSingleProviderTokenSignedByConfiguredKey() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    final var authentication = singleProviderAuth("provider-a", serverA);
    final var factory = factoryFor(Map.of("provider-a", serverA.oidcConfiguration("test-client")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = serverA.sign(serverA.issuerUri());

    final var jwt = decoder.decode(token);

    assertThat(jwt.getIssuer().toString()).isEqualTo(serverA.issuerUri());
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  @Test
  void shouldDecodeWhenTheRedirectUriCouldNotBeServedByThisApplication() throws Exception {
    // given an API-only scope whose redirect-uri names no callback this application serves
    serverA = OidcTestServer.startRsa("key-a");
    final var authentication = singleProviderAuth("provider-a", serverA);
    authentication.getOidc().setRedirectUri("https://example.com");
    final var factory = factoryFor(Map.of("provider-a", serverA.oidcConfiguration("test-client")));

    // when nothing on this path redirects a browser, so the callback is never used
    final var decoder = factory.buildIssuerAwareDecoder(authentication);

    // then
    assertThat(decoder.decode(serverA.sign(serverA.issuerUri())).getSubject()).isEqualTo("alice");
  }

  @Test
  void shouldRejectSingleProviderTokenWithUnknownIssuer() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    final var authentication = singleProviderAuth("provider-a", serverA);
    final var factory = factoryFor(Map.of("provider-a", serverA.oidcConfiguration("test-client")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    // Token signed by a known key but claiming an unregistered issuer → issuer validator rejects it
    final var tokenWrongIssuer = serverA.sign("https://unknown-idp.example.com");

    assertThatThrownBy(() -> decoder.decode(tokenWrongIssuer)).isInstanceOf(BadJwtException.class);
  }

  // ---------------------------------------------------------------------------
  // Two providers
  // ---------------------------------------------------------------------------

  @Test
  void shouldDecodeTwoProvidersTokenFromProviderA() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = serverA.sign(serverA.issuerUri());

    final var jwt = decoder.decode(token);

    assertThat(jwt.getIssuer().toString()).isEqualTo(serverA.issuerUri());
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  @Test
  void shouldDecodeTwoProvidersTokenFromProviderB() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = serverB.sign(serverB.issuerUri());

    final var jwt = decoder.decode(token);

    assertThat(jwt.getIssuer().toString()).isEqualTo(serverB.issuerUri());
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  // ---------------------------------------------------------------------------
  // Shared-issuer / different-audience isolation
  // ---------------------------------------------------------------------------

  /**
   * Two scopes share the SAME issuer (same JWKS server) but each declares a DIFFERENT audience.
   * Scope A expects {@code aud-a}; scope B expects {@code aud-b}. A token carrying {@code aud-a}
   * must be accepted by scope A's decoder and rejected by scope B's decoder — even though both
   * scopes have the same issuer URI.
   *
   * <p>This test guards the fix for the defect where the per-scope decoder reused the global {@link
   * TokenValidatorFactory} singleton, causing audience validation to be performed against the
   * global (root) audiences rather than the scope's own audiences.
   */
  @Test
  void shouldEnforcePerScopeAudienceIsolationWhenScopesShareSameIssuer() throws Exception {
    serverA = OidcTestServer.startRsa("shared-key");
    final var issuer = serverA.issuerUri();

    // Scope A: same issuer, audience = aud-a
    final var oidcA = serverA.oidcConfiguration("client-a");
    oidcA.setAudiences(Set.of("aud-a"));
    final var authA = new AuthenticationConfiguration();
    authA.setOidc(oidcA);

    // Scope B: same issuer, audience = aud-b
    final var oidcB = serverA.oidcConfiguration("client-b");
    oidcB.setAudiences(Set.of("aud-b"));
    final var authB = new AuthenticationConfiguration();
    authB.setOidc(oidcB);

    // Each scope gets its own factory (scope-specific providers map)
    final var factoryA = factoryFor(Map.of("oidc", oidcA));
    final var factoryB = factoryFor(Map.of("oidc", oidcB));

    final var decoderA = factoryA.buildIssuerAwareDecoder(authA);
    final var decoderB = factoryB.buildIssuerAwareDecoder(authB);

    // Token issued for aud-a
    final var tokenForAudA = serverA.signWithAudience(issuer, List.of("aud-a"));

    // Scope A accepts it
    final var jwt = decoderA.decode(tokenForAudA);
    assertThat(jwt.getAudience()).containsExactly("aud-a");

    // Scope B rejects it — audience mismatch
    assertThatThrownBy(() -> decoderB.decode(tokenForAudA)).isInstanceOf(BadJwtException.class);
  }

  // ---------------------------------------------------------------------------
  // Empty providers
  // ---------------------------------------------------------------------------

  @Test
  void shouldThrowIllegalStateWhenNoProvidersConfigured() {
    final var authentication = new AuthenticationConfiguration();
    authentication.setMethod(io.camunda.security.api.model.config.AuthenticationMethod.OIDC);
    final var factory = factoryFor(Map.of());

    assertThatThrownBy(() -> factory.buildIssuerAwareDecoder(authentication))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("OIDC provider")
        .hasMessageContaining("AuthenticationConfiguration");
  }

  @Test
  void shouldRejectSeveralProvidersWhenOneSetsNoIssuerUri() throws Exception {
    // given two providers in one scope, one configured with explicit endpoints and no issuer-uri
    serverA = OidcTestServer.startRsa("key-a");
    final var authentication = new AuthenticationConfiguration();
    authentication
        .getProviders()
        .getOidc()
        .put("provider-a", serverA.oidcConfiguration("client-a"));
    authentication
        .getProviders()
        .getOidc()
        .put(
            "provider-b",
            OidcConfiguration.builder()
                .clientId("client-b")
                .redirectUri("{baseUrl}/sso-callback")
                .authorizationUri(serverA.issuerUri() + "/auth")
                .tokenUri(serverA.issuerUri() + "/token")
                .jwkSetUri(serverA.jwksUri())
                .build());
    final var factory = factoryFor(authentication.getProviders().getOidc());

    // when / then the issuer-aware decoder cannot route without an issuer per provider, and seeing
    // that needs no discovery, so it fails where the chain is built
    assertThatThrownBy(() -> factory.buildIssuerAwareDecoder(authentication))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("provider-b");
  }

  @Test
  void shouldRejectTwoProvidersTokenWithUnknownIssuer() throws Exception {
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var tokenUnknownIssuer = serverA.sign("https://unregistered-idp.example.com");

    assertThatThrownBy(() -> decoder.decode(tokenUnknownIssuer))
        .isInstanceOf(BadJwtException.class)
        .hasMessageContaining("unregistered-idp");
  }

  // ---------------------------------------------------------------------------
  // One provider that does not answer
  // ---------------------------------------------------------------------------

  @Test
  void shouldDecodeTheTokenOfAProviderThatAnswersWhileAnotherProviderDoesNot() throws Exception {
    // given two providers that each need OIDC discovery, and one of them does not answer
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var providers = discoveredProviders(serverA, serverB);
    final var factory = factoryFor(providers);
    final var decoder = factory.buildIssuerAwareDecoder(auth(providers));
    serverB.failNextDiscoveryRequests(Integer.MAX_VALUE);

    // when a token of the provider that answers arrives
    final var jwt = decoder.decode(serverA.sign(serverA.issuerUri()));

    // then it decodes, because the decoder resolves the issuer of the token alone
    assertThat(jwt.getSubject()).isEqualTo("alice");
    assertThat(serverB.discoveryRequestCount()).isZero();
  }

  @Test
  void shouldFailTheTokenOfAProviderThatDoesNotAnswerAsAServerError() throws Exception {
    // given two providers that each need OIDC discovery, and one of them does not answer
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var providers = discoveredProviders(serverA, serverB);
    final var factory = factoryFor(providers);
    final var decoder = factory.buildIssuerAwareDecoder(auth(providers));
    serverB.failNextDiscoveryRequests(Integer.MAX_VALUE);
    final var tokenOfB = serverB.sign(serverB.issuerUri());

    // when / then the provider is the reason and not the token, so the chain answers with a server
    // error, as it does for a JWKS outage, and not with a refused credential
    assertThatThrownBy(() -> decoder.decode(tokenOfB))
        .isInstanceOf(JwtException.class)
        .isNotInstanceOf(BadJwtException.class)
        .hasMessageContaining(serverB.issuerUri());
  }

  @Test
  void shouldDecodeTheTokenOfAProviderThatAnswersAgain() throws Exception {
    // given a provider whose discovery failed for one token
    serverA = OidcTestServer.startRsa("key-a");
    serverB = OidcTestServer.startRsa("key-b");
    final var providers = discoveredProviders(serverA, serverB);
    final var factory = factoryFor(providers);
    final var decoder = factory.buildIssuerAwareDecoder(auth(providers));
    serverB.failNextDiscoveryRequests(1);
    final var tokenOfB = serverB.sign(serverB.issuerUri());
    assertThatThrownBy(() -> decoder.decode(tokenOfB)).isInstanceOf(JwtException.class);

    // when the provider answers again, on the same decoder
    final var jwt = decoder.decode(tokenOfB);

    // then the next token of that issuer decodes, and the deployment needs no restart
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private static AuthenticationConfiguration singleProviderAuth(
      final String registrationId, final OidcTestServer server) {
    final var auth = new AuthenticationConfiguration();
    final var oidc = server.oidcConfiguration("test-client");
    oidc.setRegistrationId(registrationId);
    auth.setOidc(oidc);
    return auth;
  }

  /**
   * A provider that sets its issuer-uri alone, so a registration of it needs OIDC discovery. The
   * other helpers set explicit endpoints, which need no network access at all.
   */
  private static OidcConfiguration discoveredProvider(
      final OidcTestServer server, final String clientId) {
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(server.issuerUri())
        .build();
  }

  private static Map<String, OidcConfiguration> discoveredProviders(
      final OidcTestServer a, final OidcTestServer b) {
    return Map.of(
        "provider-a", discoveredProvider(a, "client-a"),
        "provider-b", discoveredProvider(b, "client-b"));
  }

  private static AuthenticationConfiguration auth(final Map<String, OidcConfiguration> providers) {
    final var authentication = new AuthenticationConfiguration();
    authentication.getProviders().getOidc().putAll(providers);
    return authentication;
  }

  private static AuthenticationConfiguration twoProviderAuth(
      final OidcTestServer a, final OidcTestServer b) {
    final var auth = new AuthenticationConfiguration();
    auth.getProviders().getOidc().put("provider-a", a.oidcConfiguration("client-a"));
    auth.getProviders().getOidc().put("provider-b", b.oidcConfiguration("client-b"));
    return auth;
  }
}
