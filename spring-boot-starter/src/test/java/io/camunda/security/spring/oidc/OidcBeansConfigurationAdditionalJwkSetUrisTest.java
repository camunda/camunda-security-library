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
import io.camunda.security.spring.converter.AdditionalJwkSetUrisByRegistrationId;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Verifies the {@code additionalJwkSetUrisByRegistrationId} bean that supplies {@code
 * OidcUserAuthenticationConverter} with per-registration supplementary JWK Set URIs. The keying is
 * the point of camunda-security-library#649: a provider with no {@code issuer-uri} must still
 * contribute its URIs, which an issuer-keyed lookup cannot express.
 */
final class OidcBeansConfigurationAdditionalJwkSetUrisTest {

  private static final String SECONDARY_JWKS = "https://secondary.example.com/jwks";
  private static final String ENTRA_JWKS = "https://entra.example.com/jwks";

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
  void resolvesAdditionalUrisForAProviderConfiguredWithoutIssuerUri() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.authorization-uri=https://flat.example.com/auth",
            "camunda.security.authentication.oidc.token-uri=https://flat.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://flat.example.com/jwks",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=" + SECONDARY_JWKS)
        .run(
            ctx ->
                assertThat(byRegistrationId(ctx))
                    .containsExactly(Map.entry("oidc", List.of(SECONDARY_JWKS))));
  }

  @Test
  void resolvesAdditionalUrisForAProviderConfiguredWithIssuerUri() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=" + SECONDARY_JWKS)
        .run(
            ctx ->
                assertThat(byRegistrationId(ctx))
                    .containsExactly(Map.entry("oidc", List.of(SECONDARY_JWKS))));
  }

  @Test
  void keepsEachProviderUrisUnderItsOwnRegistrationId() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=" + SECONDARY_JWKS,
            "camunda.security.authentication.providers.oidc.entra.client-id=entra-client",
            "camunda.security.authentication.providers.oidc.entra.issuer-uri=https://entra.example.com",
            "camunda.security.authentication.providers.oidc.entra.additional-jwk-set-uris[0]="
                + ENTRA_JWKS)
        .run(
            ctx ->
                assertThat(byRegistrationId(ctx))
                    .containsOnly(
                        Map.entry("oidc", List.of(SECONDARY_JWKS)),
                        Map.entry("entra", List.of(ENTRA_JWKS))));
  }

  @Test
  void omitsProvidersThatDeclareNoAdditionalUris() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com")
        .run(ctx -> assertThat(byRegistrationId(ctx)).isEmpty());
  }

  @Test
  void omitsAProviderWhoseRegistrationIdIsBlank() {
    // A blank key could never match a ClientRegistration's registrationId, so it would only be
    // dead weight. Mirrors the filtering the neighbouring claims-converter bean applies.
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com",
            "camunda.security.authentication.oidc.registration-id=",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=" + SECONDARY_JWKS)
        .run(ctx -> assertThat(byRegistrationId(ctx)).isEmpty());
  }

  @Test
  void backsOffWhenTheHostRegistersItsOwnLookup() {
    final var hostLookup =
        new AdditionalJwkSetUrisByRegistrationId(Map.of("host", List.of(ENTRA_JWKS)));
    runner
        .withBean(AdditionalJwkSetUrisByRegistrationId.class, () -> hostLookup)
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-client",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com",
            "camunda.security.authentication.oidc.additional-jwk-set-uris[0]=" + SECONDARY_JWKS)
        .run(
            ctx ->
                assertThat(ctx.getBean(AdditionalJwkSetUrisByRegistrationId.class))
                    .isSameAs(hostLookup));
  }

  private static Map<String, List<String>> byRegistrationId(final ApplicationContext ctx) {
    return ctx.getBean(AdditionalJwkSetUrisByRegistrationId.class).byRegistrationId();
  }

  /** Stubs the OIDC infrastructure beans this test does not exercise. */
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
