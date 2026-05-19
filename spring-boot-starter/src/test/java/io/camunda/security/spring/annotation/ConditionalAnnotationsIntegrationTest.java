/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.annotation;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.AuthenticationMethod;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class ConditionalAnnotationsIntegrationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner().withUserConfiguration(ConditionalBeansConfiguration.class);

  @Test
  void conditionalOnAuthenticationMethodDefaultsToBasicWhenUnset() {
    runner.run(
        context -> {
          assertThat(context).hasBean("basicOnlyBean");
          assertThat(context).doesNotHaveBean("oidcOnlyBean");
        });
  }

  @Test
  void conditionalOnAuthenticationMethodMatchesOidcWhenConfigured() {
    runner
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .run(
            context -> {
              assertThat(context).hasBean("oidcOnlyBean");
              assertThat(context).doesNotHaveBean("basicOnlyBean");
            });
  }

  @Test
  void conditionalOnProtectedApiMatchesByDefault() {
    runner.run(
        context -> {
          assertThat(context).hasBean("protectedApiBean");
          assertThat(context).doesNotHaveBean("unprotectedApiBean");
        });
  }

  @Test
  void conditionalOnUnprotectedApiMatchesWhenEnabled() {
    runner
        .withPropertyValues("camunda.security.authentication.unprotected-api=true")
        .run(
            context -> {
              assertThat(context).hasBean("unprotectedApiBean");
              assertThat(context).doesNotHaveBean("protectedApiBean");
            });
  }

  @Test
  void conditionalOnInternalUserManagementIsDisabledForOidc() {
    runner
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .run(context -> assertThat(context).doesNotHaveBean("internalUserManagementBean"));
  }

  @Test
  void conditionalOnCamundaGroupsEnabledMatchesWhenGroupsClaimIsUnset() {
    runner.run(context -> assertThat(context).hasBean("camundaGroupsBean"));
  }

  @Test
  void conditionalOnCamundaGroupsEnabledDoesNotMatchWhenGroupsClaimIsConfigured() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.groupsClaim=groups")
        .run(context -> assertThat(context).doesNotHaveBean("camundaGroupsBean"));
  }

  @Configuration
  static class ConditionalBeansConfiguration {

    @Bean
    @ConditionalOnAuthenticationMethod(AuthenticationMethod.BASIC)
    String basicOnlyBean() {
      return "basic";
    }

    @Bean
    @ConditionalOnAuthenticationMethod(AuthenticationMethod.OIDC)
    String oidcOnlyBean() {
      return "oidc";
    }

    @Bean
    @ConditionalOnProtectedApi
    String protectedApiBean() {
      return "protected";
    }

    @Bean
    @ConditionalOnUnprotectedApi
    String unprotectedApiBean() {
      return "unprotected";
    }

    @Bean
    @ConditionalOnInternalUserManagement
    String internalUserManagementBean() {
      return "users";
    }

    @Bean
    @ConditionalOnCamundaGroupsEnabled
    String camundaGroupsBean() {
      return "groups";
    }
  }
}
