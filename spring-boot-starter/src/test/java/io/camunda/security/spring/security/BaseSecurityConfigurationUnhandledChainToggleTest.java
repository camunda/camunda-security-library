/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Verifies that the catch-all deny chain can be suppressed via {@code
 * camunda.security.authentication.catch-all-unhandled-paths-enabled=false}, which a host with its
 * own {@code /**} webapp chain (Optimize, ADR-0038) needs so the two catch-all matchers do not
 * collide.
 */
class BaseSecurityConfigurationUnhandledChainToggleTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(Paths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, BaseSecurityConfiguration.class));

  @Test
  void denyChainPresentByDefault() {
    runner.run(ctx -> assertThat(ctx).hasBean("protectedUnhandledPathsSecurityFilterChain"));
  }

  @Test
  void denyChainSuppressedWhenDisabled() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.catch-all-unhandled-paths-enabled=false")
        .run(ctx -> assertThat(ctx).doesNotHaveBean("protectedUnhandledPathsSecurityFilterChain"));
  }

  @Configuration
  static class Paths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }
}
