/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * End-to-end decode test for the composite {@code JwtDecoder} path in {@link
 * OidcBeansConfiguration}. Two local HTTP servers stand in for the primary and a secondary JWKS
 * endpoint; each serves a JWK for a freshly generated key pair. Tokens are signed with the matching
 * private key and decoded through the real Spring-built {@link JwtDecoder} bean to prove the {@link
 * CompositeJWKSource} → {@code JWSVerificationKeySelector} → {@code NimbusJwtDecoder(jwtProcessor)}
 * wiring resolves both sources, across both RSA and EC algorithm families.
 */
final class OidcBeansConfigurationCompositeJwtDecodeTest {

  private JwksTestServer primary;
  private JwksTestServer secondary;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcBeansConfiguration.class));

  @BeforeEach
  void initFields() {
    primary = null;
    secondary = null;
  }

  @AfterEach
  void stopJwksServers() {
    if (primary != null) {
      primary.stop();
    }
    if (secondary != null) {
      secondary.stop();
    }
  }

  @Test
  void shouldDecodeTokenSignedByPrimaryKey() throws Exception {
    primary = JwksTestServer.startRsa("primary-rsa");
    secondary = JwksTestServer.startRsa("secondary-rsa");
    runDecodeTest(primary);
  }

  @Test
  void shouldDecodeTokenSignedBySecondaryKey() throws Exception {
    primary = JwksTestServer.startRsa("primary-rsa");
    secondary = JwksTestServer.startRsa("secondary-rsa");
    runDecodeTest(secondary);
  }

  @Test
  void shouldDecodeTokenSignedByEcKeyOnSecondary() throws Exception {
    // Mixed-algorithm scenario: RSA primary, EC secondary. Proves the uniform RS+EC algorithm set
    // is honoured on the composite path and that the composite resolves keys of different curves
    // across sources.
    primary = JwksTestServer.startRsa("primary-rsa");
    secondary = JwksTestServer.startEc("secondary-ec");
    runDecodeTest(secondary);
  }

  private void runDecodeTest(final JwksTestServer signingKey) {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=" + primary.jwksUri(),
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]="
                + secondary.jwksUri())
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var token = sign(signingKey);

              final var jwt = decoder.decode(token);

              assertThat(jwt.getSubject()).isEqualTo("alice");
              assertThat(jwt.getHeaders()).containsEntry("kid", signingKey.kid());
            });
  }

  private static String sign(final JwksTestServer key) throws JOSEException {
    final var header = new JWSHeader.Builder(key.algorithm()).keyID(key.kid()).build();
    final var claims =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    final var jwt = new SignedJWT(header, claims);
    jwt.sign(key.signer());
    return jwt.serialize();
  }

  /**
   * Standalone JWKS HTTP server backed by a freshly generated key pair. Serves the public key as
   * JSON at {@code /jwks} on a loopback ephemeral port. The {@link #signer()} signs tokens in the
   * test using the matching private key.
   */
  private static final class JwksTestServer {
    private final HttpServer server;
    private final String kid;
    private final JWSAlgorithm algorithm;
    private final JWSSigner signer;

    private JwksTestServer(
        final HttpServer server,
        final String kid,
        final JWSAlgorithm algorithm,
        final JWSSigner signer) {
      this.server = server;
      this.kid = kid;
      this.algorithm = algorithm;
      this.signer = signer;
    }

    static JwksTestServer startRsa(final String kid) throws Exception {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      final var pair = generator.generateKeyPair();
      final var jwk =
          new RSAKey.Builder((RSAPublicKey) pair.getPublic())
              .keyID(kid)
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .build();
      return start(
          kid, jwk, JWSAlgorithm.RS256, new RSASSASigner((RSAPrivateKey) pair.getPrivate()));
    }

    static JwksTestServer startEc(final String kid) throws Exception {
      final var generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      final var pair = generator.generateKeyPair();
      final var jwk =
          new ECKey.Builder(Curve.P_256, (ECPublicKey) pair.getPublic())
              .keyID(kid)
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.ES256)
              .build();
      return start(kid, jwk, JWSAlgorithm.ES256, new ECDSASigner((ECPrivateKey) pair.getPrivate()));
    }

    private static JwksTestServer start(
        final String kid, final JWK jwk, final JWSAlgorithm algorithm, final JWSSigner signer)
        throws IOException {
      final var jwksJson = new JWKSet(jwk).toPublicJWKSet().toString();
      final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      httpServer.createContext(
          "/jwks",
          (final HttpExchange exchange) -> {
            try (exchange) {
              final byte[] body = jwksJson.getBytes(StandardCharsets.UTF_8);
              exchange.getResponseHeaders().add("Content-Type", "application/json");
              exchange.sendResponseHeaders(200, body.length);
              exchange.getResponseBody().write(body);
            } catch (final IOException ex) {
              throw new IllegalStateException("Failed to serve JWKS", ex);
            }
          });
      httpServer.start();
      return new JwksTestServer(httpServer, kid, algorithm, signer);
    }

    String kid() {
      return kid;
    }

    JWSAlgorithm algorithm() {
      return algorithm;
    }

    JWSSigner signer() {
      return signer;
    }

    String jwksUri() {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    void stop() {
      server.stop(0);
    }
  }

  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
      return request -> null;
    }
  }
}
