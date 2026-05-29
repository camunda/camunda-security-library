/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
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
  void shouldDefaultPersistentSessionToDisabled() {
    runner.run(
        context -> {
          final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
          assertThat(properties.getSession()).isNotNull();
          assertThat(properties.getSession().getPersistent().isEnabled()).isFalse();
        });
  }

  @Test
  void shouldBindPersistentSessionEnabled() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              assertThat(properties.getSession().getPersistent().isEnabled()).isTrue();
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
  void shouldRestoreEmptyOidcMapWhenProvidersSetterCalledWithNull() {
    final var providers = new OidcProvidersConfiguration();
    providers.setOidc(null);
    assertThat(providers.getOidc()).isNotNull().isEmpty();
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

  @Test
  void shouldAcceptIdWithTilde() {
    runner.run(
        context -> {
          final var securityConfiguration = context.getBean(CamundaSecurityLibraryProperties.class);
          final var pattern = securityConfiguration.getCompiledIdValidationPattern();

          assertThat(pattern.matcher("id_with_special_char~").matches()).isTrue();
        });
  }

  @Test
  void shouldDenyIdWithExclamationMark() {
    runner.run(
        context -> {
          final var securityConfiguration = context.getBean(CamundaSecurityLibraryProperties.class);
          final var pattern = securityConfiguration.getCompiledIdValidationPattern();

          assertThat(pattern.matcher("id_with_not_allowed_special_char!").matches()).isFalse();
        });
  }

  @Test
  void shouldFailFastWhenIdValidationPatternIsInvalidRegex() {
    runner
        .withPropertyValues("camunda.security.id-validation-pattern=[")
        .run(
            context -> {
              assertThat(context).hasFailed();
              assertThat(context.getStartupFailure())
                  .hasCauseInstanceOf(IllegalStateException.class);
              assertThat(context.getStartupFailure().getCause())
                  .hasMessage("Invalid regex for camunda.security.id-validation-pattern: [");
            });
  }

  @Test
  void shouldFailFastWhenIdValidationPatternIsNull() throws Exception {
    final var properties = new CamundaSecurityLibraryProperties();
    final var field =
        CamundaSecurityLibraryProperties.class.getDeclaredField("idValidationPattern");
    field.setAccessible(true);
    field.set(properties, null);

    assertThatThrownBy(properties::validate)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("camunda.security.id-validation-pattern must not be null");
  }

  @Test
  void shouldReturnPermissiveGroupPatternWhenGroupsClaimIsConfigured() {
    runner
        .withPropertyValues("camunda.security.authentication.oidc.groups-claim=groups")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              final var pattern = properties.getCompiledGroupIdValidationPattern();

              assertThat(pattern.pattern())
                  .isEqualTo(
                      CamundaSecurityLibraryProperties.DEFAULT_EXTERNAL_ID_PATTERN.pattern());
              assertThat(pattern.matcher("any!value@with#special$chars").matches()).isTrue();
            });
  }

  @Test
  void shouldReturnIdValidationPatternForGroupsWhenGroupsClaimIsNotConfigured() {
    runner.run(
        context -> {
          final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
          final var groupPattern = properties.getCompiledGroupIdValidationPattern();

          assertThat(groupPattern.pattern())
              .isEqualTo(properties.getCompiledIdValidationPattern().pattern());
          assertThat(groupPattern.matcher("valid-id_123").matches()).isTrue();
          assertThat(groupPattern.matcher("invalid!id").matches()).isFalse();
        });
  }

  @Test
  void shouldBindInitializationConfigurationProperties() {
    runner
        .withPropertyValues(
            "camunda.security.initialization.users[0].username=testuser",
            "camunda.security.initialization.users[0].password=pwd123",
            "camunda.security.initialization.users[0].name=Test User",
            "camunda.security.initialization.users[0].email=test@example.com")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              final var initialization = properties.getInitialization();

              assertThat(initialization.getUsers()).hasSize(1);
              final var user = initialization.getUsers().get(0);
              assertThat(user.getUsername()).isEqualTo("testuser");
              assertThat(user.getPassword()).isEqualTo("pwd123");
              assertThat(user.getName()).isEqualTo("Test User");
              assertThat(user.getEmail()).isEqualTo("test@example.com");
            });
  }

  @Test
  void shouldBindMultipleInitializationEntitiesWithNesting() {
    runner
        .withPropertyValues(
            "camunda.security.initialization.users[0].username=user1",
            "camunda.security.initialization.roles[0].role-id=admin",
            "camunda.security.initialization.roles[0].name=Administrator",
            "camunda.security.initialization.tenants[0].tenant-id=tenant1",
            "camunda.security.initialization.tenants[0].name=Tenant One")
        .run(
            context -> {
              final var properties = context.getBean(CamundaSecurityLibraryProperties.class);
              final var init = properties.getInitialization();

              assertThat(init.getUsers()).hasSize(1).extracting("username").contains("user1");
              assertThat(init.getRoles())
                  .hasSize(1)
                  .extracting("roleId", "name")
                  .contains(tuple("admin", "Administrator"));
              assertThat(init.getTenants())
                  .hasSize(1)
                  .extracting("tenantId", "name")
                  .contains(tuple("tenant1", "Tenant One"));
            });
  }
}
