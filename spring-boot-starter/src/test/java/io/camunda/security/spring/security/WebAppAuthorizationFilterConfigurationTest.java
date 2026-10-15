/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.authz.AuthorizationCheckerConfiguration;
import io.camunda.security.spring.authz.AuthorizationConfiguration;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandlerPort;
import io.camunda.security.spring.spi.WebAppAuthorizationEnabledPort;
import io.camunda.security.spring.spi.WebAppProviderPort;
import io.camunda.security.spring.testsupport.PermissiveAuthorizationCheckPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class WebAppAuthorizationFilterConfigurationTest {

  // Use AutoConfigurations.of(...) so @ConditionalOnBean evaluates after user configurations have
  // registered their beans — the same approach CamundaSecurityConfigurationTest takes for the
  // explicitly-imported configuration classes governed by ADR-0003.
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(StubPathPort.class)
          .withConfiguration(AutoConfigurations.of(WebAppAuthorizationFilterConfiguration.class));

  private final ApplicationContextRunner filterRunner =
      runner
          .withUserConfiguration(DenyingAuthorizationCheckPort.class, StubWebAppProvider.class)
          .withBean(
              CamundaAuthenticationProvider.class,
              () -> () -> CamundaAuthentication.of(b -> b.user("alice")));

  @Test
  void noWebAppProviderRegistersNoFilterAndNoDeniedHandler() {
    // Without any host SPI registered, the configuration must not produce the filter or the default
    // deny handler.
    runner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(WebAppAuthorizationCheckFilter.class);
          assertThat(ctx).doesNotHaveBean(WebAppAccessDeniedHandlerPort.class);
        });
  }

  @Test
  void allSpisRegisteredCreatesFilterAndDefaultHandler() {
    runner
        .withUserConfiguration(StubAuthorizationCheckPort.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(WebAppAuthorizationCheckFilter.class);
              assertThat(ctx)
                  .getBean(WebAppAccessDeniedHandlerPort.class)
                  .isInstanceOf(RedirectingWebAppAccessDeniedAdapter.class);
            });
  }

  @Test
  void absentAuthorizationCheckPortOmitsFilter() {
    // The filter is the webapp enforcement choke point. It must not materialise unless the host
    // supplies an AuthorizationCheckPort — otherwise webapp authorization would silently turn off.
    runner
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).doesNotHaveBean(AuthorizationCheckPort.class);
              assertThat(ctx).doesNotHaveBean(WebAppAuthorizationCheckFilter.class);
            });
  }

  @Test
  void defaultAuthorizationCheckPortWiredFromScopeRepositoryPortCreatesFilter() {
    // Exercises the actual production wiring chain the breaking-change note tells hosts to rely
    // on: AuthorizationScopeRepositoryPort -> AuthorizationCheckerConfiguration
    // (AuthorizationChecker)
    // -> AuthorizationConfiguration (AuthorizationService as the AuthorizationCheckPort) ->
    // WebAppAuthorizationFilterConfiguration (the filter). If that chain breaks, this must fail
    // instead of silently leaving webapp enforcement fail-open.
    new ApplicationContextRunner()
        .withUserConfiguration(StubPathPort.class)
        .withUserConfiguration(StubAuthorizationScopeRepositoryPort.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                AuthorizationCheckerConfiguration.class,
                AuthorizationConfiguration.class,
                WebAppAuthorizationFilterConfiguration.class))
        .withBean(LazyTokenClaimsConverter.class, () -> mock(LazyTokenClaimsConverter.class))
        .run(
            ctx -> {
              assertThat(ctx)
                  .getBean(AuthorizationCheckPort.class)
                  .isInstanceOf(AuthorizationService.class);
              assertThat(ctx).hasSingleBean(WebAppAuthorizationCheckFilter.class);
            });
  }

  @Test
  void hostWebAppAccessDeniedHandlerOverridesDefault() {
    runner
        .withUserConfiguration(StubAuthorizationCheckPort.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .withUserConfiguration(CustomDeniedHandler.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(WebAppAccessDeniedHandlerPort.class);
              assertThat(ctx)
                  .getBean(WebAppAccessDeniedHandlerPort.class)
                  .isInstanceOf(CustomDeniedHandler.NoOpHandler.class);
            });
  }

  @Test
  void hostAuthorizationEnabledPortOverridesGlobalFlag() {
    filterRunner
        .withPropertyValues("camunda.security.authorizations.enabled=false")
        .withBean(WebAppAuthorizationEnabledPort.class, () -> request -> true)
        .run(
            ctx -> {
              final var response = new MockHttpServletResponse();
              final var chain = filterOperateRequest(ctx, response);

              assertThat(chain.getRequest()).isNull();
              assertThat(response.getRedirectedUrl()).isEqualTo("/operate/forbidden");
            });
  }

  @Test
  void hostAuthorizationEnabledPortCanDisableGlobalFlag() {
    filterRunner
        .withPropertyValues("camunda.security.authorizations.enabled=true")
        .withBean(WebAppAuthorizationEnabledPort.class, () -> request -> false)
        .run(
            ctx -> {
              final var response = new MockHttpServletResponse();
              final var chain = filterOperateRequest(ctx, response);

              assertThat(chain.getRequest()).isNotNull();
              assertThat(response.getRedirectedUrl()).isNull();
            });
  }

  @Test
  void globalFlagAppliesWithoutHostAuthorizationEnabledPort() {
    filterRunner
        .withPropertyValues("camunda.security.authorizations.enabled=false")
        .run(
            ctx -> {
              final var response = new MockHttpServletResponse();
              final var chain = filterOperateRequest(ctx, response);

              assertThat(chain.getRequest()).isNotNull();
              assertThat(response.getRedirectedUrl()).isNull();
            });
  }

  private static MockFilterChain filterOperateRequest(
      final ApplicationContext ctx, final MockHttpServletResponse response) throws Exception {
    final var request = new MockHttpServletRequest();
    request.setRequestURI("/operate/processes");
    final var chain = new MockFilterChain();
    ctx.getBean(WebAppAuthorizationCheckFilter.class).doFilter(request, response, chain);
    return chain;
  }

  @Configuration
  static class DenyingAuthorizationCheckPort {

    @Bean
    AuthorizationCheckPort authorizationCheckPort() {
      return new AuthorizationCheckPort() {
        @Override
        public <T> Either<AuthorizationRejection, Void> check(
            final CamundaAuthentication authentication,
            final RequiredAuthorization<T> authorization) {
          return Either.left(
              new AuthorizationRejection.Permission(
                  AuthorizationResourceType.COMPONENT, PermissionType.ACCESS, "denied"));
        }

        @Override
        public <T> Either<AuthorizationRejection, Void> check(
            final Map<String, Object> claims, final RequiredAuthorization<T> authorization) {
          throw new UnsupportedOperationException();
        }

        @Override
        public <T> Either<AuthorizationRejection, Void> check(
            final CamundaAuthentication authentication,
            final RequiredAuthorization<T> authorization,
            final T resource) {
          throw new UnsupportedOperationException();
        }
      };
    }
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
      };
    }
  }

  @Configuration
  static class StubAuthorizationCheckPort {

    @Bean
    AuthorizationCheckPort authorizationCheckPort() {
      return new PermissiveAuthorizationCheckPort();
    }
  }

  @Configuration
  static class StubAuthorizationScopeRepositoryPort {

    @Bean
    AuthorizationScopeRepositoryPort authorizationScopeRepositoryPort() {
      return new NoopPort();
    }
  }

  private static final class NoopPort implements AuthorizationScopeRepositoryPort {

    @Override
    public List<AuthorizationScope> findAuthorizedScopes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType) {
      return List.of();
    }

    @Override
    public boolean hasAuthorizedScope(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final PermissionType permissionType,
        final List<String> resourceIds) {
      return false;
    }

    @Override
    public Set<PermissionType> findPermissionTypes(
        final Map<EntityType, Set<String>> ownerIds,
        final AuthorizationResourceType resourceType,
        final List<String> resourceIds) {
      return Set.of();
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
  static class CustomDeniedHandler {

    @Bean
    WebAppAccessDeniedHandlerPort customDeniedHandler() {
      return new NoOpHandler();
    }

    static final class NoOpHandler implements WebAppAccessDeniedHandlerPort {
      @Override
      public void handle(
          final HttpServletRequest request,
          final HttpServletResponse response,
          final String webApp,
          final CamundaAuthentication authentication) {}
    }
  }
}
