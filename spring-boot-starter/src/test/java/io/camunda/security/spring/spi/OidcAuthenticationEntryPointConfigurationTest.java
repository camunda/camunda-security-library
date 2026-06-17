/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticationException;

class OidcAuthenticationEntryPointConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(OidcAuthenticationEntryPointConfiguration.class));

  @Test
  void defaultBeanIsRegisteredWhenNoHostBeanIsPresent() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasSingleBean(OidcAuthenticationEntryPoint.class)
                .getBean(OidcAuthenticationEntryPoint.class)
                .isNotNull());
  }

  @Test
  void hostBeanOverridesDefaultWhenPresent() {
    runner
        .withUserConfiguration(HostEntryPoint.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(OidcAuthenticationEntryPoint.class)
                    .getBean(OidcAuthenticationEntryPoint.class)
                    .isInstanceOf(HostEntryPoint.StubEntryPoint.class));
  }

  @Configuration
  static class HostEntryPoint {

    @Bean
    OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
      return new StubEntryPoint();
    }

    static final class StubEntryPoint implements OidcAuthenticationEntryPoint {
      @Override
      public void commence(
          final HttpServletRequest request,
          final HttpServletResponse response,
          final AuthenticationException authException)
          throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }
    }
  }
}
