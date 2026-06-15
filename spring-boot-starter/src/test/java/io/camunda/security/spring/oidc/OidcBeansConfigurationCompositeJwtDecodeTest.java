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

import io.camunda.security.spring.CamundaSecurityConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * End-to-end decode test for the composite {@code JwtDecoder} path in {@link
 * OidcBeansConfiguration}. Two local HTTP servers stand in for the primary and a secondary JWKS
 * endpoint; each serves a JWK for a freshly generated key pair. Tokens are signed with the matching
 * private key and decoded through the real Spring-built {@link JwtDecoder} bean to prove the {@link
 * CompositeJWKSource} → {@code JWSVerificationKeySelector} → {@code NimbusJwtDecoder(jwtProcessor)}
 * wiring resolves both sources, across both RSA and EC algorithm families.
 */
final class OidcBeansConfigurationCompositeJwtDecodeTest {

  private OidcTestServer primary;
  private OidcTestServer secondary;

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
    primary = OidcTestServer.startRsa("primary-rsa");
    secondary = OidcTestServer.startRsa("secondary-rsa");
    runDecodeTest(primary);
  }

  @Test
  void shouldDecodeTokenSignedBySecondaryKey() throws Exception {
    primary = OidcTestServer.startRsa("primary-rsa");
    secondary = OidcTestServer.startRsa("secondary-rsa");
    runDecodeTest(secondary);
  }

  @Test
  void shouldDecodeTokenSignedByEcKeyOnSecondary() throws Exception {
    // Mixed-algorithm scenario: RSA primary, EC secondary. Proves the uniform RS+EC algorithm set
    // is honoured on the composite path and that the composite resolves keys of different curves
    // across sources.
    primary = OidcTestServer.startRsa("primary-rsa");
    secondary = OidcTestServer.startEc("secondary-ec");
    runDecodeTest(secondary);
  }

  @Test
  void shouldDecodeEcTokenOnSingleUriPath() throws Exception {
    // No additional-jwk-set-uris configured — exercises the single-URI builder path. Proves the
    // uniform RSA+EC algorithm set is applied to that path too (Spring's default would be
    // RS256-only).
    primary = OidcTestServer.startEc("primary-ec");
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=" + primary.jwksUri())
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var token = primary.sign();

              final var jwt = decoder.decode(token);

              assertThat(jwt.getSubject()).isEqualTo("alice");
              assertThat(jwt.getHeaders()).containsEntry("kid", primary.kid());
            });
  }

  @Test
  void shouldRejectTokenWithWrongIssuerOnCompositePath() throws Exception {
    // issuer-uri is set alongside jwk-set-uri + additional-jwk-set-uris. The composite decoder
    // must apply the issuer validator — a token signed by a valid key but carrying a different
    // 'iss' claim must be rejected.
    primary = OidcTestServer.startRsa("primary-rsa");
    secondary = OidcTestServer.startRsa("secondary-rsa");
    final var expectedIssuer = "https://expected-issuer.example.com";
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.issuer-uri=" + expectedIssuer,
            "camunda.security.authentication.oidc.jwk-set-uri=" + primary.jwksUri(),
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]="
                + secondary.jwksUri())
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new InMemoryClientRegistrationRepository(
                    testRegistration("oidc", primary.jwksUri(), expectedIssuer)))
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var goodToken = primary.sign(expectedIssuer);
              final var spoofedToken = primary.sign("https://attacker.example.com");

              assertThat(decoder.decode(goodToken).getIssuer().toString())
                  .isEqualTo(expectedIssuer);
              assertThatThrownBy(() -> decoder.decode(spoofedToken))
                  .isInstanceOf(JwtException.class);
            });
  }

  private void runDecodeTest(final OidcTestServer signingKey) {
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
              final var token = signingKey.sign();

              final var jwt = decoder.decode(token);

              assertThat(jwt.getSubject()).isEqualTo("alice");
              assertThat(jwt.getHeaders()).containsEntry("kid", signingKey.kid());
            });
  }

  private static ClientRegistration testRegistration(
      final String registrationId, final String jwkSetUri, final String issuerUri) {
    final var builder =
        ClientRegistration.withRegistrationId(registrationId)
            .clientId("test-client")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationUri("https://example.com/auth")
            .tokenUri("https://example.com/token")
            .jwkSetUri(jwkSetUri)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
    if (issuerUri != null) {
      builder.issuerUri(issuerUri);
    }
    return builder.build();
  }

  /** Stubs OIDC infrastructure beans other than {@link JwtDecoder}. */
  @Configuration
  static class StubOidcInfrastructure {

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
