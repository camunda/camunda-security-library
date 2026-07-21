/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
 * Verifies the single {@link JwtDecoder} bean resolves correctly across all configuration shapes.
 * With one registration a single-issuer {@code NimbusJwtDecoder} is built; with multiple
 * registrations an issuer-aware decoder is built; with zero registrations startup fails. Per-issuer
 * audience enforcement and additional JWK set URIs are also covered.
 */
class OidcBeansConfigurationJwtDecoderTest {

  private static OidcTestServer server;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class));

  @BeforeAll
  static void startServer() throws Exception {
    server = OidcTestServer.startRsa("typ-test");
  }

  @AfterAll
  static void stopServer() {
    if (server != null) {
      server.stop();
      server = null;
    }
  }

  @Test
  void shouldBuildJwtDecoderFromFlatJwkSetUri() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks")
        .run(ctx -> assertThat(ctx).hasSingleBean(JwtDecoder.class));
  }

  @Test
  void shouldBuildJwtDecoderForSingleProviderEntry() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://foo.example.com/auth",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks")
        .run(ctx -> assertThat(ctx).hasSingleBean(JwtDecoder.class));
  }

  @Test
  void shouldBuildIssuerAwareJwtDecoderForMultipleProviders() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
            "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.keycloak.issuer-uri=https://kc.example.com",
            "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
            "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
            "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri=https://kc.example.com/jwks",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
            "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.azure.issuer-uri=https://az.example.com",
            "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
            "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
            "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=https://az.example.com/jwks")
        .withUserConfiguration(TwoProviderRegistrations.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
              final var decoder = ctx.getBean(JwtDecoder.class);
              // Both registered issuers route past the issuer check to the JWK fetch step.
              // The JWK URIs are unreachable in tests, so we get a network/fetch error —
              // but not "Unknown issuer", which proves the routing reached the right provider.
              assertThatThrownBy(() -> decoder.decode(tokenWithIssuer("https://kc.example.com")))
                  .isInstanceOf(JwtException.class)
                  .hasMessageNotContaining("Unknown issuer");
              assertThatThrownBy(() -> decoder.decode(tokenWithIssuer("https://az.example.com")))
                  .isInstanceOf(JwtException.class)
                  .hasMessageNotContaining("Unknown issuer");
              // An unregistered issuer must be rejected before the JWK fetch.
              assertThatThrownBy(
                      () -> decoder.decode(tokenWithIssuer("https://unknown.example.com")))
                  .isInstanceOf(JwtException.class)
                  .hasMessageContaining("Unknown issuer");
            });
  }

  @Test
  void shouldFailWithInformativeErrorWhenRegistrationRepositoryIsEmpty() {
    runner
        .withUserConfiguration(EmptyRegistrationRepository.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("empty")
                  .hasMessageContaining("providers.oidc");
            });
  }

  @Test
  void shouldFailWithInformativeErrorWhenOnlyAdditionalJwkSetUrisConfigured() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks")
        // additional-jwk-set-uris without a primary jwk-set-uri or issuer-uri:
        // clientRegistrationRepository fails with an actionable error
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("issuer-uri")
                  .hasMessageContaining("jwk-set-uri");
            });
  }

  @Test
  void shouldFailWithInformativeErrorWhenNoSourceAvailable() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token")
        // no issuer-uri, no jwk-set-uri: clientRegistrationRepository fails with an
        // actionable error before jwtDecoder is even attempted
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("issuer-uri")
                  .hasMessageContaining("jwk-set-uri")
                  .hasMessageContaining("providers.oidc");
            });
  }

  @Test
  void shouldBuildJwtDecoderWithAdditionalJwkSetUris() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://primary.example.com/jwks",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[1]=https://tertiary.example.com/jwks")
        .run(ctx -> assertThat(ctx).hasSingleBean(JwtDecoder.class));
  }

  @Test
  void shouldIgnoreBlankAdditionalJwkSetUris() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://primary.example.com/jwks",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[1]=https://secondary.example.com/jwks")
        .run(ctx -> assertThat(ctx).hasSingleBean(JwtDecoder.class));
  }

  @Test
  void shouldFailWhenAdditionalJwkSetUrisIsSetButRegistrationHasNoJwkSetUri() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks")
        .withUserConfiguration(NoJwkSetUriRegistration.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalArgumentException.class)
                  .hasMessageContaining("jwk-set-uri");
            });
  }

  /** Returns a runner configured against the live {@link OidcTestServer} for full-decode tests. */
  private ApplicationContextRunner serverRunner() {
    return runner.withPropertyValues(
        "camunda.security.authentication.oidc.client-id=test-client",
        "camunda.security.authentication.oidc.redirect-uri="
            + "{baseUrl}/login/oauth2/code/{registrationId}",
        "camunda.security.authentication.oidc.authorization-uri=" + server.issuerUri() + "/auth",
        "camunda.security.authentication.oidc.token-uri=" + server.issuerUri() + "/token",
        "camunda.security.authentication.oidc.jwk-set-uri=" + server.jwksUri());
  }

  private static String tokenWithIssuer(final String issuer) {
    final var header =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("{\"alg\":\"RS256\"}".getBytes(UTF_8));
    final var payload =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(("{\"iss\":\"" + issuer + "\"}").getBytes(UTF_8));
    return header + "." + payload + ".fakesig";
  }

  private static String tokenWithTypAndIssuer(final String typ, final String issuer) {
    final var header =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(("{\"alg\":\"RS256\",\"typ\":\"" + typ + "\"}").getBytes(UTF_8));
    final var payload =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(("{\"iss\":\"" + issuer + "\"}").getBytes(UTF_8));
    return header + "." + payload + ".fakesig";
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

  @Test
  void shouldDecodeTokenWithTypJwt() throws Exception {
    serverRunner()
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var jwt = decoder.decode(server.signWithTyp(server.issuerUri(), "JWT"));
              assertThat(jwt.getSubject()).isEqualTo("alice");
            });
  }

  @Test
  void shouldDecodeTokenWithTypAtJwt() throws Exception {
    serverRunner()
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var jwt = decoder.decode(server.signWithTyp(server.issuerUri(), "at+jwt"));
              assertThat(jwt.getSubject()).isEqualTo("alice");
            });
  }

  @Test
  void shouldDecodeTokenWithNoTyp() throws Exception {
    // OidcTestServer.sign() builds a JWSHeader without a typ field — the lenient
    // setAllowEmpty(true) flag must allow it through.
    serverRunner()
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var jwt = decoder.decode(server.sign(server.issuerUri()));
              assertThat(jwt.getSubject()).isEqualTo("alice");
            });
  }

  @Test
  void shouldRejectTokenWithUnexpectedTyp() {
    // id+jwt is not in the allowed set; the JOSE type check fires before JWK lookup,
    // so a fake signature is sufficient to trigger the rejection path.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri="
                + "{baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks")
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              assertThatThrownBy(
                      () ->
                          decoder.decode(
                              tokenWithTypAndIssuer("id+jwt", "https://flat.example.com")))
                  .isInstanceOf(JwtException.class)
                  // Nimbus message: "JOSE header 'typ' (type) 'id+jwt' not allowed"
                  .hasMessageContaining("typ")
                  .hasMessageContaining("id+jwt");
            });
  }

  @Test
  void hostSuppliedJwtDecoderTakesPrecedenceViaConditionalOnMissingBean() {
    // @ConditionalOnMissingBean on OidcBeansConfiguration#jwtDecoder must back off
    // when the host registers its own JwtDecoder bean.
    final JwtDecoder customDecoder =
        token -> {
          throw new JwtException("custom JwtDecoder should not be invoked in this test");
        };
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri="
                + "{baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks")
        .withBean(JwtDecoder.class, () -> customDecoder)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
              assertThat(ctx.getBean(JwtDecoder.class)).isSameAs(customDecoder);
            });
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

  /**
   * Provides a pre-built two-provider {@link ClientRegistrationRepository} for the multi-issuer
   * test. In production, CSL's {@code clientRegistrationRepository} bean builds registrations via
   * {@code ClientRegistrations.fromIssuerLocation(issuerUri)} (OIDC discovery). The test properties
   * use fake URIs that cannot do real discovery, so this class supplies equivalent registrations
   * directly, bypassing the network call.
   */
  @Configuration
  static class TwoProviderRegistrations {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          List.of(
              testRegistration("keycloak", "https://kc.example.com/jwks", "https://kc.example.com"),
              testRegistration("azure", "https://az.example.com/jwks", "https://az.example.com")));
    }
  }

  /** Empty repository — used to test the empty-registrations failure path in {@code jwtDecoder}. */
  @Configuration
  static class EmptyRegistrationRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new EmptyIterableClientRegistrationRepository();
    }

    private static final class EmptyIterableClientRegistrationRepository
        implements ClientRegistrationRepository, Iterable<ClientRegistration> {

      @Override
      public ClientRegistration findByRegistrationId(final String registrationId) {
        return null;
      }

      @Override
      public java.util.Iterator<ClientRegistration> iterator() {
        return java.util.Collections.emptyIterator();
      }
    }
  }

  /** Single registration without a jwk-set-uri — used to test the failure path. */
  @Configuration
  static class NoJwkSetUriRegistration {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          ClientRegistration.withRegistrationId("oidc")
              .clientId("flat-client")
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .authorizationUri("https://flat.example.com/auth")
              .tokenUri("https://flat.example.com/token")
              .issuerUri("https://flat.example.com")
              .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
              .build());
    }
  }
}
