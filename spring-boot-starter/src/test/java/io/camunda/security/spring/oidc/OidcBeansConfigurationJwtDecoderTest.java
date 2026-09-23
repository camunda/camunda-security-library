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

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
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
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Verifies the single {@link JwtDecoder} bean resolves correctly across all configuration shapes.
 * With one registration a single-issuer {@code NimbusJwtDecoder} is built; with multiple
 * registrations an issuer-aware decoder is built; with zero registrations startup fails. Per-issuer
 * audience enforcement and additional JWK set URIs are also covered.
 */
class OidcBeansConfigurationJwtDecoderTest {

  /**
   * Two providers, of which azure sets no issuer-uri. The issuer-aware decoder needs one issuer per
   * provider, so this configuration separates the repositories that the requirement applies to from
   * those it does not.
   */
  private static final String[] TWO_PROVIDERS_ONE_WITHOUT_ISSUER_URI = {
    "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
    "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
    "camunda.security.authentication.providers.oidc.keycloak.issuer-uri=https://kc.example.com",
    "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
    "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
    "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri=https://kc.example.com/jwks",
    "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
    "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
    "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
    "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
    "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=https://az.example.com/jwks"
  };

  /**
   * Two providers that set explicit endpoints and no issuer-uri, so the library configuration
   * accepts no token of its own. A repository that carries the issuers is the only source of a
   * route.
   */
  private static final String[] TWO_PROVIDERS_WITHOUT_ISSUER_URI = {
    "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
    "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
    "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
    "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
    "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri=https://kc.example.com/jwks",
    "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
    "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
    "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
    "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
    "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=https://az.example.com/jwks"
  };

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
              assertThat(ctx).hasNotFailed();
              assertThatThrownBy(() -> ctx.getBean(JwtDecoder.class).decode("any-token"))
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("empty")
                  .hasMessageContaining("providers.oidc");
            });
  }

  @Test
  void shouldFailAtStartupWhenOneOfSeveralProvidersSetsNoIssuerUri() {
    // given two providers, one of them configured with explicit endpoints and no issuer-uri
    runner
        .withPropertyValues(TWO_PROVIDERS_ONE_WITHOUT_ISSUER_URI)
        // the issuer-aware decoder routes tokens by their issuer, so it needs one per provider;
        // that needs no discovery to see, so it must not wait for the first token decode
        .run(
            ctx ->
                assertThat(ctx)
                    .getFailure()
                    .hasMessageContaining("issuerUri")
                    .hasMessageContaining("azure"));
  }

  @Test
  void shouldStartWhenAHostRepositoryReplacesTheRegistrationsOfTheProviderMap() {
    // given a host repository that holds one issuer-aware registration, while the provider map sets
    // no issuer-uri for one of its two providers
    runner
        .withUserConfiguration(SingleRegistrationRepository.class)
        .withPropertyValues(TWO_PROVIDERS_ONE_WITHOUT_ISSUER_URI)
        // the provider map describes registrations the library did not build, so the requirement of
        // the issuer-aware decoder belongs to the registrations of the host repository, and the
        // decoder checks those at the first token decode
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
            });
  }

  @Test
  void shouldWarnRatherThanFailWhenOnlyAdditionalJwkSetUrisConfigured() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks")
        // additional-jwk-set-uris without a primary jwk-set-uri or issuer-uri: incomplete, but
        // only logged now — building the registration is deferred, so this does not stop the
        // context from starting
        .run(ctx -> assertThat(ctx).hasNotFailed());
  }

  @Test
  void shouldWarnRatherThanFailWhenNoSourceAvailable() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token")
        // no issuer-uri, no jwk-set-uri: incomplete, but only logged now
        .run(ctx -> assertThat(ctx).hasNotFailed());
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
              assertThat(ctx).hasNotFailed();
              assertThatThrownBy(() -> ctx.getBean(JwtDecoder.class).decode("any-token"))
                  .rootCause()
                  .isInstanceOf(IllegalArgumentException.class)
                  .hasMessageContaining("jwk-set-uri");
            });
  }

  @Test
  void shouldDecodeTheTokenOfAProviderThatAnswersWhileAnotherProviderDoesNot() throws Exception {
    // given two providers that each need OIDC discovery, and one of them does not answer
    try (final var answering = OidcTestServer.startRsa("answering");
        final var silent = OidcTestServer.startRsa("silent")) {
      silent.failNextDiscoveryRequests(Integer.MAX_VALUE);
      runner
          .withPropertyValues(discoveredProviders(answering, silent))
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();
                final var decoder = ctx.getBean(JwtDecoder.class);

                // then a token of the provider that answers decodes, because the decoder resolves
                // the issuer of the token alone
                final var jwt = decoder.decode(answering.sign(answering.issuerUri()));
                assertThat(jwt.getSubject()).isEqualTo("alice");

                // and the token of the other provider is the only one that fails, as a server error
                final var tokenOfTheSilentProvider = silent.sign(silent.issuerUri());
                assertThatThrownBy(() -> decoder.decode(tokenOfTheSilentProvider))
                    .isInstanceOf(JwtException.class)
                    .isNotInstanceOf(BadJwtException.class)
                    .hasMessageContaining(silent.issuerUri());
              });
    }
  }

  @Test
  void shouldRouteATokenByTheIssuersOfAHostLazyRepository() throws Exception {
    // given a host repository of the library's lazy type that holds its own providers under the
    // registrationIds of the library configuration, which declares no issuer-uri at all
    try (final var alpha = OidcTestServer.startRsa("alpha");
        final var beta = OidcTestServer.startRsa("beta")) {
      runner
          .withPropertyValues(TWO_PROVIDERS_WITHOUT_ISSUER_URI)
          .withBean(
              ClientRegistrationRepository.class,
              () ->
                  new LazyClientRegistrationRepository(
                      new ScopedClientRegistrationFactory(),
                      Map.of(
                          "keycloak",
                          hostProvider(alpha.issuerUri()),
                          "azure",
                          hostProvider(beta.issuerUri()))))
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();
                final var decoder = ctx.getBean(JwtDecoder.class);

                // then each token reaches the keys of the registration that declares its issuer,
                // because the routes come from the repository and not from the library
                // configuration
                assertThat(decoder.decode(alpha.sign(alpha.issuerUri())).getSubject())
                    .isEqualTo("alice");
                assertThat(decoder.decode(beta.sign(beta.issuerUri())).getSubject())
                    .isEqualTo("alice");
              });
    }
  }

  private static OidcConfiguration hostProvider(final String issuerUri) {
    final var provider = new OidcConfiguration();
    provider.setClientId("host-client");
    provider.setIssuerUri(issuerUri);
    provider.setRedirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
    return provider;
  }

  /**
   * Two providers that set their issuer-uri alone, so a registration of either needs OIDC
   * discovery. The other tests set explicit endpoints, which need no network access at all.
   */
  private static String[] discoveredProviders(
      final OidcTestServer answering, final OidcTestServer silent) {
    return new String[] {
      "camunda.security.authentication.providers.oidc.answering.client-id=answering-client",
      "camunda.security.authentication.providers.oidc.answering.redirect-uri="
          + "{baseUrl}/login/oauth2/code/{registrationId}",
      "camunda.security.authentication.providers.oidc.answering.issuer-uri="
          + answering.issuerUri(),
      "camunda.security.authentication.providers.oidc.silent.client-id=silent-client",
      "camunda.security.authentication.providers.oidc.silent.redirect-uri="
          + "{baseUrl}/login/oauth2/code/{registrationId}",
      "camunda.security.authentication.providers.oidc.silent.issuer-uri=" + silent.issuerUri()
    };
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

  @Test
  void shouldNotApplyTheAdditionalJwkSetUrisOfAProviderThatDoesNotVerifyTheIssuer()
      throws Exception {
    // given two providers of one issuer, where the provider that does not verify its tokens is the
    // one that adds a key set
    try (final var verifying = OidcTestServer.startRsa("verifying");
        final var other = OidcTestServer.startRsa("other")) {
      final var issuerUri = verifying.issuerUri();
      runner
          .withPropertyValues(
              "camunda.security.authentication.providers.oidc.provider-a.client-id=a-client",
              "camunda.security.authentication.providers.oidc.provider-a.redirect-uri="
                  + "{baseUrl}/login/oauth2/code/{registrationId}",
              "camunda.security.authentication.providers.oidc.provider-a.issuer-uri=" + issuerUri,
              "camunda.security.authentication.providers.oidc.provider-a.authorization-uri="
                  + issuerUri
                  + "/auth",
              "camunda.security.authentication.providers.oidc.provider-a.token-uri="
                  + issuerUri
                  + "/token",
              "camunda.security.authentication.providers.oidc.provider-a.jwk-set-uri="
                  + verifying.jwksUri(),
              "camunda.security.authentication.providers.oidc.provider-b.client-id=b-client",
              "camunda.security.authentication.providers.oidc.provider-b.redirect-uri="
                  + "{baseUrl}/login/oauth2/code/{registrationId}",
              "camunda.security.authentication.providers.oidc.provider-b.issuer-uri=" + issuerUri,
              "camunda.security.authentication.providers.oidc.provider-b.authorization-uri="
                  + issuerUri
                  + "/auth",
              "camunda.security.authentication.providers.oidc.provider-b.token-uri="
                  + issuerUri
                  + "/token",
              "camunda.security.authentication.providers.oidc.provider-b.jwk-set-uri="
                  + verifying.jwksUri(),
              "camunda.security.authentication.providers.oidc.provider-b.additional-jwk-set-uris[0]="
                  + other.jwksUri())
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();
                final var decoder = ctx.getBean(JwtDecoder.class);

                // then the keys of the provider that owns the issuer decode its tokens
                assertThat(decoder.decode(verifying.sign(issuerUri)).getSubject())
                    .isEqualTo("alice");

                // and the key set of the other provider does not, although it is configured as an
                // additional one for the same issuer
                final var tokenOfTheOtherKeySet = other.sign(issuerUri);
                assertThatThrownBy(() -> decoder.decode(tokenOfTheOtherKeySet))
                    .isInstanceOf(JwtException.class);
              });
    }
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
  @Test
  void shouldFailAtStartupWhenAHostRepositoryIsNotIterable() {
    // given a host repository the default decoder cannot read, which needs no network to detect
    runner
        .withUserConfiguration(NonIterableRegistrationRepository.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Iterable<ClientRegistration>"));
  }

  @Test
  void shouldStartWhenAHostLazyRepositoryHoldsOtherProvidersThanTheProviderMap() {
    // given a host repository of the library's lazy type, over a provider the configuration does
    // not describe, while the provider map sets no issuer-uri for one of its two providers
    runner
        .withUserConfiguration(HostLazyRegistrationRepository.class)
        .withPropertyValues(TWO_PROVIDERS_ONE_WITHOUT_ISSUER_URI)
        // the registrations of the host repository are its own, so the requirement of the
        // issuer-aware decoder belongs to them, and not to the provider map of the library
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
            });
  }

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

  /**
   * A host repository with one registration, used to show that the issuer requirement of the
   * issuer-aware decoder is made on the provider map of the library only.
   */
  @Configuration
  static class SingleRegistrationRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          testRegistration("keycloak", "https://kc.example.com/jwks", "https://kc.example.com"));
    }
  }

  /**
   * A host repository of the library's lazy type, over its own provider. Used to show that the
   * library reads the provider map only for a repository that resolves the configured providers.
   */
  @Configuration
  static class HostLazyRegistrationRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      final var provider = new OidcConfiguration();
      provider.setClientId("host-client");
      provider.setIssuerUri("https://host.example.com");
      provider.setAuthorizationUri("https://host.example.com/auth");
      provider.setTokenUri("https://host.example.com/token");
      provider.setJwkSetUri("https://host.example.com/jwks");
      provider.setRedirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
      return new LazyClientRegistrationRepository(
          new ScopedClientRegistrationFactory(), Map.of("host", provider));
    }
  }

  /** A host repository of a shape the default decoder cannot read. */
  @Configuration
  static class NonIterableRegistrationRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return registrationId -> null;
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
