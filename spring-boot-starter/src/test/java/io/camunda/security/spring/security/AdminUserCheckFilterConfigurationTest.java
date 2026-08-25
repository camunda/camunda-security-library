/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.spi.AdminUserMissingHandlerPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class AdminUserCheckFilterConfigurationTest {

  // Use AutoConfigurations.of(...) so @ConditionalOnBean evaluates after user configurations have
  // registered their beans — the same approach CamundaSecurityConfigurationTest takes for the
  // explicitly-imported configuration classes governed by ADR-0003.
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(StubPathPort.class)
          .withConfiguration(AutoConfigurations.of(AdminUserCheckFilterConfiguration.class));

  @Test
  void noPresencePortRegistersNoFilterAndNoDefaultHandler() {
    runner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(AdminUserCheckFilter.class);
          assertThat(ctx).doesNotHaveBean(AdminUserMissingHandlerPort.class);
        });
  }

  @Test
  void presencePortPresentCreatesFilterAndDefaultHandler() {
    runner
        .withUserConfiguration(StubPresencePort.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AdminUserCheckFilter.class);
              assertThat(ctx)
                  .getBean(AdminUserMissingHandlerPort.class)
                  .isInstanceOf(RedirectingAdminUserMissingAdapter.class);
            });
  }

  @Test
  void hostAdminUserMissingHandlerOverridesDefault() {
    runner
        .withUserConfiguration(StubPresencePort.class)
        .withUserConfiguration(CustomMissingHandler.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AdminUserMissingHandlerPort.class);
              assertThat(ctx)
                  .getBean(AdminUserMissingHandlerPort.class)
                  .isInstanceOf(CustomMissingHandler.NoOpHandler.class);
              assertThat(ctx).hasSingleBean(AdminUserCheckFilter.class);
            });
  }

  @Configuration
  static class StubPathPort {

    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/api/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of();
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of("/operate/**");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of("operate");
        }

        @Override
        public Set<String> adminFilterBypassPaths() {
          return Set.of("/admin/setup", "/admin/assets");
        }
      };
    }
  }

  @Configuration
  static class StubPresencePort {

    @Bean
    AdminUserPresencePort adminUserPresencePort() {
      return () -> true;
    }
  }

  @Configuration
  static class CustomMissingHandler {

    @Bean
    AdminUserMissingHandlerPort customMissingHandler() {
      return new NoOpHandler();
    }

    static final class NoOpHandler implements AdminUserMissingHandlerPort {
      @Override
      public void handle(final HttpServletRequest request, final HttpServletResponse response) {}
    }
  }
}
