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
 * Verifies the {@link ClientRegistrationRepository} produced by {@link OidcBeansConfiguration}.
 * Flat {@code authentication.oidc.*} and multi-provider {@code authentication.providers.oidc.*} are
 * additive: the flat block contributes one registration keyed by its own {@code registrationId}
 * when {@code clientId} is set, and the providers map is merged on top so a colliding provider id
 * overwrites the flat entry — mirroring OC's {@code OidcAuthenticationConfigurationRepository}.
 * Uses explicit endpoint URIs throughout so no network is required; the {@code issuer-uri}
 * discovery path is exercised by the host-side integration tests, not here.
 */
class OidcBeansConfigurationClientRegistrationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class));

  @Test
  void shouldBuildSingleRegistrationFromFlatShape() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://idp.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://idp.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://idp.example.com/jwks")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var registration = repository.findByRegistrationId("oidc");
              assertThat(registration).isNotNull();
              assertThat(registration.getClientId()).isEqualTo("flat-client");
              assertThat(registration.getRegistrationId()).isEqualTo("oidc");
            });
  }

  @Test
  void shouldBuildOneRegistrationPerEntryInProvidersOidc() {
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
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var keycloak = repository.findByRegistrationId("keycloak");
              final var azure = repository.findByRegistrationId("azure");
              assertThat(keycloak).isNotNull();
              assertThat(keycloak.getClientId()).isEqualTo("kc-client");
              assertThat(keycloak.getRegistrationId()).isEqualTo("keycloak");
              assertThat(azure).isNotNull();
              assertThat(azure.getClientId()).isEqualTo("az-client");
              assertThat(azure.getRegistrationId()).isEqualTo("azure");
            });
  }

  @Test
  void shouldRegisterFlatAndProvidersAdditivelyWhenBothShapesAreSet() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks",
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://foo.example.com/auth",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var flat = repository.findByRegistrationId("oidc");
              final var foo = repository.findByRegistrationId("foo");
              assertThat(flat).isNotNull();
              assertThat(flat.getClientId()).isEqualTo("flat-client");
              assertThat(foo).isNotNull();
              assertThat(foo.getClientId()).isEqualTo("foo-client");
            });
  }

  @Test
  void shouldLetProviderEntryOverwriteFlatOnRegistrationIdCollision() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks",
            "camunda.security.authentication.providers.oidc.oidc.client-id=provider-client",
            "camunda.security.authentication.providers.oidc.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.oidc.authorization-uri=https://provider.example.com/auth",
            "camunda.security.authentication.providers.oidc.oidc.token-uri=https://provider.example.com/token",
            "camunda.security.authentication.providers.oidc.oidc.jwk-set-uri=https://provider.example.com/jwks")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var registration = repository.findByRegistrationId("oidc");
              assertThat(registration).isNotNull();
              assertThat(registration.getClientId()).isEqualTo("provider-client");
            });
  }

  @Test
  void shouldIgnoreFlatBlockWhenClientIdIsAbsent() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks",
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://foo.example.com/auth",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              assertThat(repository.findByRegistrationId("foo")).isNotNull();
              assertThat(repository.findByRegistrationId("oidc")).isNull();
            });
  }

  @Test
  void shouldFailWithInformativeErrorWhenNeitherShapeIsConfigured() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasFailed();
          assertThat(ctx.getStartupFailure())
              .rootCause()
              .isInstanceOf(IllegalStateException.class)
              .hasMessageContaining("client-id")
              .hasMessageContaining("providers.oidc");
        });
  }

  @Test
  void shouldTreatBlankEndpointUrisAsMissing() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("'foo'");
            });
  }

  @Test
  void shouldFailWithActionableErrorWhenFlatRegistrationIdIsBlank() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.registration-id=",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("registrationId")
                  .hasMessageContaining("registration-id");
            });
  }

  @Test
  void shouldPopulateUserInfoUriOnRegistrationByDefault() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://foo.example.com/auth",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks",
            "camunda.security.authentication.providers.oidc.foo.user-info-uri=https://foo.example.com/userinfo")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var registration = repository.findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri())
                  .isEqualTo("https://foo.example.com/userinfo");
            });
  }

  @Test
  void shouldNullUserInfoUriOnRegistrationWhenUserInfoEnabledIsFalse() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.foo.authorization-uri=https://foo.example.com/auth",
            "camunda.security.authentication.providers.oidc.foo.token-uri=https://foo.example.com/token",
            "camunda.security.authentication.providers.oidc.foo.jwk-set-uri=https://foo.example.com/jwks",
            "camunda.security.authentication.providers.oidc.foo.user-info-uri=https://foo.example.com/userinfo",
            "camunda.security.authentication.providers.oidc.foo.user-info-enabled=false")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var registration = repository.findByRegistrationId("foo");
              assertThat(registration).isNotNull();
              assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isNull();
            });
  }

  @Test
  void shouldHonourUserInfoEnabledPerProvider() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
            "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
            "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
            "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri=https://kc.example.com/jwks",
            "camunda.security.authentication.providers.oidc.keycloak.user-info-uri=https://kc.example.com/userinfo",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
            "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
            "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
            "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=https://az.example.com/jwks",
            "camunda.security.authentication.providers.oidc.azure.user-info-uri=https://az.example.com/userinfo",
            "camunda.security.authentication.providers.oidc.azure.user-info-enabled=false")
        .run(
            ctx -> {
              final var repository = ctx.getBean(ClientRegistrationRepository.class);
              final var keycloak = repository.findByRegistrationId("keycloak");
              final var azure = repository.findByRegistrationId("azure");
              assertThat(keycloak).isNotNull();
              assertThat(azure).isNotNull();
              assertThat(keycloak.getProviderDetails().getUserInfoEndpoint().getUri())
                  .isEqualTo("https://kc.example.com/userinfo");
              assertThat(azure.getProviderDetails().getUserInfoEndpoint().getUri()).isNull();
            });
  }

  @Test
  void shouldReportRegistrationIdAndBothShapesWhenBuilderFailsForProvider() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-client",
            "camunda.security.authentication.providers.oidc.foo.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .rootCause()
                  .isInstanceOf(IllegalStateException.class)
                  .hasMessageContaining("'foo'")
                  .hasMessageContaining("providers.oidc.foo");
            });
  }

  /**
   * Provides stub beans for the OIDC infrastructure {@link OidcBeansConfiguration} would otherwise
   * eagerly create (JwtDecoder, OAuth2AuthorizedClientRepository, OAuth2AuthorizedClientManager).
   * The bean under test, {@link ClientRegistrationRepository}, is intentionally not stubbed so the
   * real bean is exercised.
   */
  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub");
      };
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
