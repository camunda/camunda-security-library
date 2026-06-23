/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AuthorizationConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, AuthorizationConfiguration.class));

  @Test
  void beanIsRegisteredWhenAuthorizationCheckerIsPresent() {
    runner
        .withBean(AuthorizationChecker.class, () -> mock(AuthorizationChecker.class))
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void beanIsAbsentWhenAuthorizationCheckerIsMissing() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(AuthorizationService.class));
  }

  @Test
  void beanIsRegisteredWhenCheckerIsInSeparateUserConfiguration() {
    // Correct host pattern: checker in a separate @Configuration, service via AutoConfigurations.
    new ApplicationContextRunner()
        .withUserConfiguration(SeparateCheckerConfiguration.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class, AuthorizationConfiguration.class))
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void hostCanOverrideAuthorizationService() {
    final var custom = mock(AuthorizationService.class);
    runner
        .withBean(AuthorizationChecker.class, () -> mock(AuthorizationChecker.class))
        .withBean(AuthorizationService.class, () -> custom)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(AuthorizationService.class)
                    .getBean(AuthorizationService.class)
                    .isSameAs(custom));
  }

  @Test
  void propertyEvaluatorsAreInjected() {
    @SuppressWarnings("unchecked")
    final PropertyAuthorizationEvaluator<Object> evaluator =
        (PropertyAuthorizationEvaluator<Object>) mock(PropertyAuthorizationEvaluator.class);
    when(evaluator.propertyName()).thenReturn("assignee");
    runner
        .withBean(AuthorizationChecker.class, () -> mock(AuthorizationChecker.class))
        .withBean(PropertyAuthorizationEvaluator.class, () -> evaluator)
        .run(ctx -> assertThat(ctx).hasSingleBean(AuthorizationService.class));
  }

  @Test
  void authorizationServiceUsesPropertiesFlags() {
    runner
        .withPropertyValues(
            "camunda.security.authorizations.enabled=false",
            "camunda.security.multiTenancy.checksEnabled=false")
        .withBean(AuthorizationChecker.class, () -> mock(AuthorizationChecker.class))
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AuthorizationService.class);
              final var service = ctx.getBean(AuthorizationService.class);
              // Both disabled → skipChecks() must be true
              assertThat(service.skipChecks()).isTrue();
            });
  }

  @Configuration
  static class SeparateCheckerConfiguration {
    @Bean
    AuthorizationChecker separateChecker() {
      return mock(AuthorizationChecker.class);
    }
  }
}
