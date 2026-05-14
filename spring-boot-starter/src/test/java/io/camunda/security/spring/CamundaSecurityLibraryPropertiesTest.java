/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class CamundaSecurityLibraryPropertiesTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(CamundaSecurityConfiguration.class));

  @Test
  void shouldValidateNestedOidcAssertionConfigurationAfterBinding() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.assertion.kid-encoding=BASE64URL",
            "camunda.security.authentication.oidc.assertion.kid-case=LOWER")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasRootCauseInstanceOf(IllegalStateException.class)
                  .hasRootCauseMessage("kidCase can only be set when kidEncoding is HEX");
            });
  }

  @Test
  void shouldDefaultProvidersOidcToEmptyMap() {
    runner.run(
        context -> {
          final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
          assertThat(properties.getAuthentication().getProviders()).isNotNull();
          assertThat(properties.getAuthentication().getProviders().getOidc()).isEmpty();
        });
  }

  @Test
  void shouldRestoreEmptyProvidersWhenSetterCalledWithNull() {
    final var authentication = new AuthenticationConfiguration();
    authentication.setProviders(null);
    assertThat(authentication.getProviders()).isNotNull();
    assertThat(authentication.getProviders().getOidc()).isEmpty();
  }

  @Test
  void shouldBindSingleProviderUnderProvidersOidc() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.foo.client-id=abc",
            "camunda.security.authentication.providers.oidc.foo.issuer-uri=https://example.com")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              final var providers = properties.getAuthentication().getProviders().getOidc();
              assertThat(providers).containsOnlyKeys("foo");
              assertThat(providers.get("foo").getClientId()).isEqualTo("abc");
              assertThat(providers.get("foo").getIssuerUri()).isEqualTo("https://example.com");
            });
  }

  @Test
  void shouldBindMultipleProvidersUnderProvidersOidc() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-id",
            "camunda.security.authentication.providers.oidc.keycloak.issuer-uri=https://kc.example.com",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-id",
            "camunda.security.authentication.providers.oidc.azure.issuer-uri=https://az.example.com")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              final var providers = properties.getAuthentication().getProviders().getOidc();
              assertThat(providers).containsOnlyKeys("keycloak", "azure");
              assertThat(providers.get("keycloak").getClientId()).isEqualTo("kc-id");
              assertThat(providers.get("azure").getClientId()).isEqualTo("az-id");
            });
  }

  @Test
  void shouldStillBindFlatOidcShape() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-id",
            "camunda.security.authentication.oidc.issuer-uri=https://flat.example.com")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              assertThat(properties.getAuthentication().getOidc().getClientId())
                  .isEqualTo("flat-id");
              assertThat(properties.getAuthentication().getOidc().getIssuerUri())
                  .isEqualTo("https://flat.example.com");
              assertThat(properties.getAuthentication().getProviders().getOidc()).isEmpty();
            });
  }

  @Test
  void shouldAllowBothFlatAndProvidersShapesToBindWithoutFailing() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.oidc.client-id=flat-id",
            "camunda.security.authentication.providers.oidc.foo.client-id=foo-id")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              assertThat(properties.getAuthentication().getOidc().getClientId())
                  .isEqualTo("flat-id");
              assertThat(
                      properties
                          .getAuthentication()
                          .getProviders()
                          .getOidc()
                          .get("foo")
                          .getClientId())
                  .isEqualTo("foo-id");
            });
  }
}
