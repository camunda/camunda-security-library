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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;

class OidcWebappClientBeansConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=oidc");

  @Test
  void allFiveBeansArePresentWhenWebappEnabledIsUnset() {
    runner
        .withPropertyValues(
            // Explicit endpoint URIs (rather than issuer-uri) so no network call/OIDC discovery is
            // required — same approach as OidcBeansConfigurationClientRegistrationTest.
            "camunda.security.authentication.oidc.client-id=test-client",
            "camunda.security.authentication.oidc.client-secret=secret",
            "camunda.security.authentication.oidc.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.oidc.authorization-uri=https://idp.example.com/authorize",
            "camunda.security.authentication.oidc.token-uri=https://idp.example.com/token",
            "camunda.security.authentication.oidc.jwk-set-uri=https://idp.example.com/jwks")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).hasSingleBean(ClientRegistrationRepository.class);
              assertThat(context).hasSingleBean(JwtDecoder.class);
              assertThat(context).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
              assertThat(context).hasSingleBean(OAuth2AuthorizedClientRepository.class);
              assertThat(context).hasSingleBean(OAuth2AuthorizedClientManager.class);
            });
  }

  @Test
  void noneOfTheFiveBeansArePresentWhenWebappEnabledIsFalse() {
    runner
        .withPropertyValues("camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(ClientRegistrationRepository.class);
              assertThat(context).doesNotHaveBean(JwtDecoder.class);
              assertThat(context).doesNotHaveBean(OAuth2AuthorizationRequestResolver.class);
              assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientRepository.class);
              assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientManager.class);
            });
  }

  @Test
  void
      hostSuppliedJwtDecoderStartsCleanlyWhenWebappEnabledIsFalseWithNoOidcClientPropertiesConfigured() {
    // Reproduces the exact camunda-hub scenario this fix addresses: a bearer-only host supplies its
    // own JwtDecoder (built directly from jwk-set-uri, no client registration) and sets
    // webapp-enabled=false — no camunda.security.authentication.oidc.client-id or issuer-uri is
    // configured at all. Before this fix, OidcBeansConfiguration.clientRegistrationRepository()
    // still activated (gated only on method=oidc) and threw at startup.
    runner
        .withUserConfiguration(HostJwtDecoderConfig.class)
        .withPropertyValues("camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(ClientRegistrationRepository.class);
              assertThat(context)
                  .getBean(JwtDecoder.class)
                  .isSameAs(context.getBean(HostJwtDecoderConfig.class).jwtDecoder());
            });
  }

  @Configuration
  static class HostJwtDecoderConfig {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }
  }
}
