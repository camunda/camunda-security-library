/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.spring.CamundaSecurityConfiguration;
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
 * Verifies the single {@link JwtDecoder} bean resolves correctly across the additive configuration
 * shapes: it picks the flat block when configured, otherwise the first {@code providers.oidc} entry
 * with a usable issuer or JWK source. Per-audience decoding remains a host concern.
 */
class OidcBeansConfigurationJwtDecoderTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcBeansConfiguration.class));

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
  void shouldFallBackToFirstProviderJwkSetUriWhenFlatBlockIsAbsent() {
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
  void shouldFailWithInformativeErrorWhenMultipleProviderSourcesAndNoFlatBlock() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
            "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
            "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
            "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri=https://kc.example.com/jwks",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
            "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
            "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
            "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=https://az.example.com/jwks")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("multiple providers")
                  .hasMessageContaining("custom @Bean JwtDecoder");
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
  void shouldFailWhenAdditionalJwkSetUrisIsSetButPrimaryJwkSetUriIsMissing() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("additional-jwk-set-uris")
                  .hasMessageContaining("jwk-set-uri");
            });
  }

  @Test
  void shouldReportAdditionalJwkSetUrisErrorWhenNoPrimaryAnywhere() {
    // Only the additional list is set — no jwk-set-uri, no issuer-uri anywhere. The specific
    // additional-jwk-set-uris error must surface in preference to the generic "set issuer-uri or
    // jwk-set-uri" message.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=https://secondary.example.com/jwks")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("additional-jwk-set-uris")
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
        // no issuer-uri, no jwk-set-uri anywhere: JwtDecoder cannot resolve a source
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

  /**
   * Stubs the OIDC infrastructure beans other than {@link JwtDecoder} so the bean under test is the
   * one exercised. {@link ClientRegistrationRepository} is also stubbed because a misconfigured
   * flat block (used in the negative test) would otherwise fail its construction first.
   */
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
