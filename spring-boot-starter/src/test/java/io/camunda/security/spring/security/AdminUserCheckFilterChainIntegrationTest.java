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
import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.Authorization;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.spi.WebAppProviderPort;
import jakarta.servlet.Filter;
import java.util.List;
import java.util.Optional;
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
 * Verifies the chain-assembly contract for {@link AdminUserCheckFilter}: the bean is created
 * whenever a host registers the required SPIs alongside the explicit
 * {@code @Import(AdminUserCheckFilterConfiguration.class)}, but only the Basic-auth webapp chain
 * wires it via {@code addFilterAfter(...)}. The OIDC webapp chain intentionally omits the filter
 * even when the bean is present (see ADR-0011 and GH-189). Hosts that need the check on a custom
 * OIDC chain are expected to compose the bean themselves.
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
                  AdminUserCheckFilterConfiguration.class,
                  WebAppAuthorizationFilterConfiguration.class))
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
                  ScopedOidcInfrastructureConfiguration.class,
                  AdminUserCheckFilterConfiguration.class,
                  WebAppAuthorizationFilterConfiguration.class))
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
  void oidcChainOmitsAdminUserCheckFilterEvenWhenBeanIsPresent() {
    // GH-189 / ADR-0011: the OIDC chain configuration does not add the admin-user check filter,
    // even when the bean exists in the context. Admin provisioning under OIDC is driven by IdP
    // claims and the filter has no signal to distinguish "no admin yet" from "this user's
    // membership has not been projected yet" — so the chain must not 302 to /admin/setup. A
    // host that wants this check under OIDC owns the wiring.
    oidcRunner
        .withUserConfiguration(StubPresencePort.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AdminUserCheckFilter.class);
              assertThat(filtersOf(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class)))
                  .noneSatisfy(f -> assertThat(f).isInstanceOf(AdminUserCheckFilter.class));
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

  @Test
  void basicChainPlacesAdminFilterBeforeWebAppFilterWhenBothSpisAreRegistered() {
    // The chain wiring anchors WebAppAuthorizationCheckFilter on AdminUserCheckFilter when both
    // are present, so the admin-presence redirect runs before any per-web-app permission check.
    basicRunner
        .withUserConfiguration(StubPresencePort.class)
        .withUserConfiguration(StubAuthorizationRepository.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .run(
            ctx -> {
              final var filters =
                  filtersOf(ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class));
              assertThat(indexOfType(filters, AdminUserCheckFilter.class))
                  .isLessThan(indexOfType(filters, WebAppAuthorizationCheckFilter.class));
            });
  }

  private static int indexOfType(final List<Filter> filters, final Class<? extends Filter> type) {
    for (int i = 0; i < filters.size(); i++) {
      if (type.isInstance(filters.get(i))) {
        return i;
      }
    }
    throw new AssertionError("No filter of type " + type.getName() + " in chain");
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
  static class StubAuthorizationRepository {

    @Bean
    AuthorizationRepositoryPort authorizationRepository() {
      return new AuthorizationRepositoryPort() {
        @Override
        public Set<Authorization> findAuthorizations(
            final CamundaAuthentication authentication, final ResourceType resourceType) {
          return Set.of();
        }
      };
    }
  }

  @Configuration
  static class StubWebAppProvider {

    @Bean
    WebAppProviderPort webAppProvider() {
      return request -> Optional.of("operate");
    }
  }

  @Configuration
  static class StubAuthenticationProvider {

    @Bean
    CamundaAuthenticationProvider camundaAuthenticationProvider() {
      return CamundaAuthentication::anonymous;
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
