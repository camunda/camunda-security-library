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
import com.nimbusds.jose.crypto.RSASSASigner;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
 * endpoint; each serves a public key for an RSA pair generated at test setup. Tokens are signed
 * with the matching private key and decoded through the real Spring-built {@link JwtDecoder} bean
 * to prove the {@link CompositeJWKSource} → {@code JWSVerificationKeySelector} → {@code
 * NimbusJwtDecoder(jwtProcessor)} wiring resolves both sources.
 */
final class OidcBeansConfigurationCompositeJwtDecodeTest {

  private RsaJwks primary;
  private RsaJwks secondary;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcBeansConfiguration.class));

  @BeforeEach
  void startJwksServers() throws Exception {
    primary = RsaJwks.start("primary-key");
    secondary = RsaJwks.start("secondary-key");
  }

  @AfterEach
  void stopJwksServers() {
    primary.stop();
    secondary.stop();
  }

  @Test
  void shouldDecodeTokenSignedByPrimaryKey() {
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
              final var token = signed(primary);

              final var jwt = decoder.decode(token);

              assertThat(jwt.getSubject()).isEqualTo("alice");
              assertThat(jwt.getHeaders()).containsEntry("kid", primary.kid());
            });
  }

  @Test
  void shouldDecodeTokenSignedBySecondaryKey() {
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
              final var token = signed(secondary);

              final var jwt = decoder.decode(token);

              assertThat(jwt.getSubject()).isEqualTo("alice");
              assertThat(jwt.getHeaders()).containsEntry("kid", secondary.kid());
            });
  }

  private static String signed(final RsaJwks key) throws JOSEException {
    final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.kid()).build();
    final var claims =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    final var jwt = new SignedJWT(header, claims);
    jwt.sign(new RSASSASigner(key.privateKey()));
    return jwt.serialize();
  }

  /**
   * Standalone JWKS HTTP server backed by a freshly generated RSA key pair. Serves the public key
   * at {@code /jwks} on a loopback ephemeral port. {@link #privateKey()} signs tokens in the test.
   */
  private static final class RsaJwks {
    private final HttpServer server;
    private final String kid;
    private final RSAPrivateKey privateKey;
    private final String jwksJson;

    private RsaJwks(
        final HttpServer server,
        final String kid,
        final RSAPrivateKey privateKey,
        final String jwksJson) {
      this.server = server;
      this.kid = kid;
      this.privateKey = privateKey;
      this.jwksJson = jwksJson;
    }

    static RsaJwks start(final String kid) throws Exception {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      final var pair = generator.generateKeyPair();
      final var publicKey = (RSAPublicKey) pair.getPublic();
      final var privateKey = (RSAPrivateKey) pair.getPrivate();
      final var jwk =
          new RSAKey.Builder(publicKey)
              .keyID(kid)
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .build();
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
      return new RsaJwks(httpServer, kid, privateKey, jwksJson);
    }

    String kid() {
      return kid;
    }

    RSAPrivateKey privateKey() {
      return privateKey;
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
