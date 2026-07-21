/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

class BasicAuthWebappEnabledPropertyTest {

  private static final String BASIC_WEBAPP_CHAIN_BEAN = "basicAuthWebappSecurityFilterChain";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsService.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  BasicAuthWebappSecurityConfiguration.class,
                  ScopedWebappSecurityChainBuilderConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  WebAppAuthorizationFilterConfiguration.class));

  @Test
  void webappChainIsPresentIfMethodPropertyIsUnset() {
    // BasicAuthWebappSecurityConfiguration's method condition is matchIfMissing = true
    runner.run(
        context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasBean(BASIC_WEBAPP_CHAIN_BEAN);
        });
  }

  @Test
  void webappChainIsPresentIfWebappEnabledIsExplicitlyTrue() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=basic",
            "camunda.security.authentication.webapp-enabled=true")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).hasBean(BASIC_WEBAPP_CHAIN_BEAN);
            });
  }

  @Test
  void webappChainIsAbsentIfWebappEnabledIsFalse() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=basic",
            "camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(BASIC_WEBAPP_CHAIN_BEAN);
            });
  }

  @Test
  void webappChainIsAbsentIfWebappEnabledIsFalseAndMethodPropertyIsUnset() {
    // matchIfMissing = true on the method condition still applies; webapp-enabled=false wins.
    runner
        .withPropertyValues("camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).doesNotHaveBean(BASIC_WEBAPP_CHAIN_BEAN);
            });
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class StubUserDetailsService {

    @Bean
    UserDetailsService userDetailsService() {
      return new InMemoryUserDetailsManager(
          User.withUsername("user").password("{noop}password").roles("USER").build());
    }
  }
}
