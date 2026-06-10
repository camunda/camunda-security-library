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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;

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

  private JwksTestServer serverA;
  private JwksTestServer serverB;

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
    serverA = JwksTestServer.start("key-a");
    final var authentication = singleProviderAuth("provider-a", serverA);
    final var factory = factoryFor(Map.of("provider-a", serverA.oidcConfiguration("test-client")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = sign(serverA, serverA.issuerUri());

    final var jwt = decoder.decode(token);

    assertThat(jwt.getIssuer().toString()).isEqualTo(serverA.issuerUri());
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  @Test
  void shouldRejectSingleProviderTokenWithUnknownIssuer() throws Exception {
    serverA = JwksTestServer.start("key-a");
    final var authentication = singleProviderAuth("provider-a", serverA);
    final var factory = factoryFor(Map.of("provider-a", serverA.oidcConfiguration("test-client")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    // Token signed by a known key but claiming an unregistered issuer → issuer validator rejects it
    final var tokenWrongIssuer = sign(serverA, "https://unknown-idp.example.com");

    assertThatThrownBy(() -> decoder.decode(tokenWrongIssuer)).isInstanceOf(BadJwtException.class);
  }

  // ---------------------------------------------------------------------------
  // Two providers
  // ---------------------------------------------------------------------------

  @Test
  void shouldDecodeTwoProvidersTokenFromProviderA() throws Exception {
    serverA = JwksTestServer.start("key-a");
    serverB = JwksTestServer.start("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = sign(serverA, serverA.issuerUri());

    final var jwt = decoder.decode(token);

    assertThat(jwt.getIssuer().toString()).isEqualTo(serverA.issuerUri());
    assertThat(jwt.getSubject()).isEqualTo("alice");
  }

  @Test
  void shouldDecodeTwoProvidersTokenFromProviderB() throws Exception {
    serverA = JwksTestServer.start("key-a");
    serverB = JwksTestServer.start("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var token = sign(serverB, serverB.issuerUri());

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
    serverA = JwksTestServer.start("shared-key");
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
    final var tokenForAudA = signWithAudience(serverA, issuer, List.of("aud-a"));

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
  void shouldRejectTwoProvidersTokenWithUnknownIssuer() throws Exception {
    serverA = JwksTestServer.start("key-a");
    serverB = JwksTestServer.start("key-b");
    final var authentication = twoProviderAuth(serverA, serverB);
    final var factory =
        factoryFor(
            Map.of(
                "provider-a", serverA.oidcConfiguration("client-a"),
                "provider-b", serverB.oidcConfiguration("client-b")));

    final var decoder = factory.buildIssuerAwareDecoder(authentication);
    final var tokenUnknownIssuer = sign(serverA, "https://unregistered-idp.example.com");

    assertThatThrownBy(() -> decoder.decode(tokenUnknownIssuer))
        .isInstanceOf(BadJwtException.class)
        .hasMessageContaining("unregistered-idp");
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private static AuthenticationConfiguration singleProviderAuth(
      final String registrationId, final JwksTestServer server) {
    final var auth = new AuthenticationConfiguration();
    final var oidc = server.oidcConfiguration("test-client");
    oidc.setRegistrationId(registrationId);
    auth.setOidc(oidc);
    return auth;
  }

  private static AuthenticationConfiguration twoProviderAuth(
      final JwksTestServer a, final JwksTestServer b) {
    final var auth = new AuthenticationConfiguration();
    auth.getProviders().getOidc().put("provider-a", a.oidcConfiguration("client-a"));
    auth.getProviders().getOidc().put("provider-b", b.oidcConfiguration("client-b"));
    return auth;
  }

  private static String sign(final JwksTestServer server, final String issuer) throws Exception {
    return signWithAudience(server, issuer, List.of());
  }

  private static String signWithAudience(
      final JwksTestServer server, final String issuer, final List<String> audiences)
      throws Exception {
    final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(server.kid()).build();
    final var builder =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issuer(issuer)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)));
    if (!audiences.isEmpty()) {
      builder.audience(audiences);
    }
    final var jwt = new SignedJWT(header, builder.build());
    jwt.sign(server.signer());
    return jwt.serialize();
  }

  /**
   * Minimal JWKS + OIDC discovery HTTP server backed by a freshly generated RSA key pair. Serves:
   *
   * <ul>
   *   <li>{@code /jwks} — the public JWK set (for token verification)
   *   <li>{@code /.well-known/openid-configuration} — a discovery document pointing back to this
   *       server (so {@link
   *       org.springframework.security.oauth2.client.registration.ClientRegistrations#fromIssuerLocation}
   *       can resolve without real external HTTP)
   * </ul>
   */
  private static final class JwksTestServer {
    private final HttpServer server;
    private final String kid;
    private final JWSSigner signer;

    private JwksTestServer(final HttpServer server, final String kid, final JWSSigner signer) {
      this.server = server;
      this.kid = kid;
      this.signer = signer;
    }

    static JwksTestServer start(final String kid) throws Exception {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      final var pair = generator.generateKeyPair();
      final var jwk =
          new RSAKey.Builder((RSAPublicKey) pair.getPublic())
              .privateKey((RSAPrivateKey) pair.getPrivate())
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .keyID(kid)
              .build();
      final var jwkSet = new JWKSet(jwk).toPublicJWKSet().toString();
      final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      final var base = "http://127.0.0.1:" + httpServer.getAddress().getPort();
      final var discoveryDoc =
          """
          {
            "issuer": "%s",
            "authorization_endpoint": "%s/auth",
            "token_endpoint": "%s/token",
            "jwks_uri": "%s/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
          }
          """
              .formatted(base, base, base, base);
      httpServer.createContext(
          "/jwks",
          exchange -> {
            final var body = jwkSet.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (exchange) {
              exchange.getResponseBody().write(body);
            }
          });
      httpServer.createContext(
          "/.well-known/openid-configuration",
          exchange -> {
            final var body = discoveryDoc.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (exchange) {
              exchange.getResponseBody().write(body);
            }
          });
      httpServer.start();
      return new JwksTestServer(httpServer, kid, new RSASSASigner(jwk));
    }

    String kid() {
      return kid;
    }

    JWSSigner signer() {
      return signer;
    }

    String issuerUri() {
      return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * Builds an {@link OidcConfiguration} backed by this server. Uses {@code issuerUri} so that
     * {@link ScopedClientRegistrationFactory} can route by issuer; all explicit endpoints override
     * the discovered values so the test does not depend on a real external IdP.
     */
    OidcConfiguration oidcConfiguration(final String clientId) {
      final var base = issuerUri();
      return OidcConfiguration.builder()
          .clientId(clientId)
          .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
          .issuerUri(base)
          .authorizationUri(base + "/auth")
          .tokenUri(base + "/token")
          .jwkSetUri(base + "/jwks")
          .build();
    }

    void stop() {
      server.stop(0);
    }
  }
}
