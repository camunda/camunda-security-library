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
import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import jakarta.servlet.Filter;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies that {@link AdminUserCheckFilter} ends up in the OIDC and Basic-auth webapp filter
 * chains when (and only when) a host registers the required SPIs alongside the explicit
 * {@code @Import(AdminUserCheckFilterConfiguration.class)}.
 */
class AdminUserCheckFilterChainIntegrationTest {

  private static final String BASIC_CHAIN_BEAN = "basicAuthWebappSecurityFilterChain";
  private static final String OIDC_CHAIN_BEAN = "oidcWebappSecurityFilterChain";

  private static final String[] OIDC_PROPERTIES = {
    "camunda.security.authentication.method=oidc",
    "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
    "camunda.security.authentication.oidc.client-id=test-client",
    "camunda.security.authentication.oidc.client-secret=secret",
    "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
    "camunda.security.authentication.oidc.token-uri=http://localhost/token",
    "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
    "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback"
  };

  private final WebApplicationContextRunner basicRunner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsService.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  BasicAuthWebappSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  AdminUserCheckFilterConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=basic");

  private final WebApplicationContextRunner oidcRunner =
      new WebApplicationContextRunner()
          .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcWebappSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class,
                  AdminUserCheckFilterConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void basicChainContainsAdminUserCheckFilterWhenSpiIsRegistered() {
    basicRunner
        .withUserConfiguration(StubPresencePort.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AdminUserCheckFilter.class);
              assertThat(filtersOf(ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class)))
                  .anySatisfy(f -> assertThat(f).isInstanceOf(AdminUserCheckFilter.class));
            });
  }

  @Test
  void basicChainOmitsAdminUserCheckFilterWhenSpiIsAbsent() {
    basicRunner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(AdminUserCheckFilter.class);
          assertThat(filtersOf(ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class)))
              .noneSatisfy(f -> assertThat(f).isInstanceOf(AdminUserCheckFilter.class));
        });
  }

  @Test
  void oidcChainContainsAdminUserCheckFilterWhenSpiIsRegistered() {
    oidcRunner
        .withUserConfiguration(StubPresencePort.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AdminUserCheckFilter.class);
              assertThat(filtersOf(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)))
                  .anySatisfy(f -> assertThat(f).isInstanceOf(AdminUserCheckFilter.class));
            });
  }

  @Test
  void oidcChainOmitsAdminUserCheckFilterWhenSpiIsAbsent() {
    oidcRunner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(AdminUserCheckFilter.class);
          assertThat(filtersOf(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)))
              .noneSatisfy(f -> assertThat(f).isInstanceOf(AdminUserCheckFilter.class));
        });
  }

  private static java.util.List<Filter> filtersOf(final SecurityFilterChain chain) {
    return ((DefaultSecurityFilterChain) chain).getFilters();
  }

  @Configuration
  static class StubPaths {

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
          return Set.of("/error");
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
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
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
