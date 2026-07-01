/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.Authorization;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandlerPort;
import io.camunda.security.spring.spi.WebAppProviderPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class WebAppAuthorizationFilterConfigurationTest {

  // Use AutoConfigurations.of(...) so @ConditionalOnBean evaluates after user configurations have
  // registered their beans — the same approach CamundaSecurityConfigurationTest takes for the
  // explicitly-imported configuration classes governed by ADR-0008.
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(StubPathPort.class)
          .withConfiguration(AutoConfigurations.of(WebAppAuthorizationFilterConfiguration.class));

  @Test
  void noWebAppProviderRegistersNoFilterAndNoDeniedHandlerAndNoDefaultService() {
    // Without any host SPI registered, the configuration must not produce any beans — neither the
    // filter, the default deny handler, nor the default ResourcePermissionService.
    runner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(WebAppAuthorizationCheckFilter.class);
          assertThat(ctx).doesNotHaveBean(WebAppAccessDeniedHandlerPort.class);
          assertThat(ctx).doesNotHaveBean(ResourcePermissionPort.class);
        });
  }

  @Test
  void authorizationRepositoryAlonePresentWiresDefaultServiceButNoFilterOrHandler() {
    // ResourcePermissionService is the default for ResourcePermissionPort whenever an
    // AuthorizationRepositoryPort exists, even before WebAppProviderPort is wired.
    runner
        .withUserConfiguration(StubAuthorizationRepository.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(ResourcePermissionPort.class);
              assertThat(ctx)
                  .getBean(ResourcePermissionPort.class)
                  .isInstanceOf(ResourcePermissionService.class);
              assertThat(ctx).doesNotHaveBean(WebAppAuthorizationCheckFilter.class);
              assertThat(ctx).doesNotHaveBean(WebAppAccessDeniedHandlerPort.class);
            });
  }

  @Test
  void authorizationDisabledMakesDefaultServiceGrantAll() {
    // With authorization disabled, the default ResourcePermissionService must grant every check
    // even though the repository holds no matching grants. The flag is read from the bound
    // properties bean enabled via @EnableConfigurationProperties on the configuration.
    runner
        .withUserConfiguration(StubAuthorizationRepository.class)
        .withPropertyValues("camunda.security.authorizations.enabled=false")
        .run(
            ctx -> {
              final ResourcePermissionPort port = ctx.getBean(ResourcePermissionPort.class);
              assertThat(
                      port.hasPermission(
                          CamundaAuthentication.anonymous(),
                          ResourceType.COMPONENT,
                          "operate",
                          PermissionType.ACCESS))
                  .isTrue();
            });
  }

  @Test
  void allThreeSpisRegisteredCreatesFilterAndDefaults() {
    runner
        .withUserConfiguration(StubAuthorizationRepository.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(WebAppAuthorizationCheckFilter.class);
              assertThat(ctx)
                  .getBean(ResourcePermissionPort.class)
                  .isInstanceOf(ResourcePermissionService.class);
              assertThat(ctx)
                  .getBean(WebAppAccessDeniedHandlerPort.class)
                  .isInstanceOf(RedirectingWebAppAccessDeniedAdapter.class);
            });
  }

  @Test
  void hostResourcePermissionPortOverridesDefaultService() {
    // A host that registers its own ResourcePermissionPort must keep it; the default service must
    // back off via @ConditionalOnMissingBean.
    runner
        .withUserConfiguration(StubAuthorizationRepository.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .withUserConfiguration(CustomResourcePermissionPort.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(ResourcePermissionPort.class);
              assertThat(ctx)
                  .getBean(ResourcePermissionPort.class)
                  .isInstanceOf(CustomResourcePermissionPort.AlwaysFalse.class);
            });
  }

  @Test
  void hostWebAppAccessDeniedHandlerOverridesDefault() {
    runner
        .withUserConfiguration(StubAuthorizationRepository.class)
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
  static class CustomResourcePermissionPort {

    @Bean
    ResourcePermissionPort customResourcePermissionPort() {
      return new AlwaysFalse();
    }

    static final class AlwaysFalse implements ResourcePermissionPort {
      @Override
      public boolean hasPermission(
          final CamundaAuthentication authentication,
          final ResourceType resourceType,
          final String resourceId,
          final PermissionType permissionType) {
        return false;
      }
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
