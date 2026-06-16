/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcTestServer;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.user.UserConfiguration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies that {@link ScopedApiChainRegistrar} registers both a scoped API chain and a scoped
 * webapp chain per descriptor, and that the webapp chain correctly matches scoped paths and
 * challenges anonymous browser requests.
 *
 * <ul>
 *   <li>With one OIDC {@link CamundaSecurityScopeProvider} descriptor, both a {@code
 *       scopedApiSecurityFilterChain-0-*} and a {@code scopedWebappSecurityFilterChain-0-*} {@link
 *       OrderedSecurityFilterChainWrapper} bean are registered.
 *   <li>The webapp chain matches paths under the scoped basePath (e.g. {@code
 *       /physical-tenants/t1/operate/dashboard}) and an anonymous browser GET returns 302.
 *   <li>With no {@link CamundaSecurityScopeProvider} bean, neither scoped chain type is registered.
 * </ul>
 */
class ScopedWebappChainRegistrationTest {

  private static final String SCOPED_BASE = "/physical-tenants/t1";
  private static final String SCOPED_OPERATE = SCOPED_BASE + "/operate/dashboard";

  // ---------------------------------------------------------------------------
  // Runner factory
  // ---------------------------------------------------------------------------

  /**
   * Creates a runner that loads the CSL chain stack (BASIC global mode) including {@link
   * ScopedApiSecurityConfiguration} (which now imports {@link
   * io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration}). Includes
   * the webapp-path stub so the webapp chain has matchers to register.
   */
  private WebApplicationContextRunner baseRunner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedApiSecurityConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  // ---------------------------------------------------------------------------
  // 1. No-op: no provider → no scoped chains of either type
  // ---------------------------------------------------------------------------

  @Test
  void noProviderRegistersNoScopedChains() {
    baseRunner()
        .run(
            ctx -> {
              final var wrappers =
                  ctx.getBeansOfType(SecurityFilterChain.class).values().stream()
                      .filter(c -> c instanceof OrderedSecurityFilterChainWrapper)
                      .toList();
              assertThat(wrappers)
                  .as("no scoped chains must be registered when no provider bean is present")
                  .isEmpty();
            });
  }

  // ---------------------------------------------------------------------------
  // 2. One OIDC descriptor → both API and webapp chain beans registered
  // ---------------------------------------------------------------------------

  @Test
  void oneOidcDescriptorRegistersBothApiAndWebappChain() throws Exception {
    final var server = OidcTestServer.startRsa("scope-key");
    try {
      final var descriptor = buildOidcDescriptor(server);

      baseRunner()
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> (CamundaSecurityScopeProvider) () -> List.of(descriptor))
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();

                final var allChainBeanNames = ctx.getBeanNamesForType(SecurityFilterChain.class);

                final var apiChainNames =
                    java.util.Arrays.stream(allChainBeanNames)
                        .filter(name -> name.startsWith("scopedApiSecurityFilterChain-0-"))
                        .toList();
                assertThat(apiChainNames)
                    .as("exactly one scoped API chain bean must be registered")
                    .hasSize(1);

                final var webappChainNames =
                    java.util.Arrays.stream(allChainBeanNames)
                        .filter(name -> name.startsWith("scopedWebappSecurityFilterChain-0-"))
                        .toList();
                assertThat(webappChainNames)
                    .as("exactly one scoped webapp chain bean must be registered")
                    .hasSize(1);

                // Both must be OrderedSecurityFilterChainWrapper instances
                final var apiChain =
                    ctx.getBean(apiChainNames.getFirst(), SecurityFilterChain.class);
                final var webappChain =
                    ctx.getBean(webappChainNames.getFirst(), SecurityFilterChain.class);
                assertThat(apiChain).isInstanceOf(OrderedSecurityFilterChainWrapper.class);
                assertThat(webappChain).isInstanceOf(OrderedSecurityFilterChainWrapper.class);
              });
    } finally {
      server.stop();
    }
  }

  // ---------------------------------------------------------------------------
  // 3. Webapp chain matches the scoped operate path and NOT an unscoped path
  // ---------------------------------------------------------------------------

  @Test
  void webappChainMatchesScopedPath() throws Exception {
    final var server = OidcTestServer.startRsa("scope-key-2");
    try {
      final var descriptor = buildOidcDescriptor(server);

      baseRunner()
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> (CamundaSecurityScopeProvider) () -> List.of(descriptor))
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();
                final var webappChain = webappChain(ctx);

                // Must match the scoped operate path
                assertThat(webappChain.matches(new MockHttpServletRequest("GET", SCOPED_OPERATE)))
                    .as("webapp chain must match requests under the scoped basePath")
                    .isTrue();

                // Must NOT match the unscoped operate path
                assertThat(
                        webappChain.matches(
                            new MockHttpServletRequest("GET", "/operate/dashboard")))
                    .as("webapp chain must NOT match requests outside the scoped basePath")
                    .isFalse();
              });
    } finally {
      server.stop();
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Webapp chain → anonymous browser GET to protected scoped path returns 302
  // ---------------------------------------------------------------------------

  @Test
  void anonymousGetToScopedWebappPathRedirectsToLogin() throws Exception {
    final var server = OidcTestServer.startRsa("scope-key-3");
    try {
      final var descriptor = buildOidcDescriptor(server);

      baseRunner()
          .withBean(
              CamundaSecurityScopeProvider.class,
              () -> (CamundaSecurityScopeProvider) () -> List.of(descriptor))
          .run(
              ctx -> {
                assertThat(ctx).hasNotFailed();
                final var webappChain = webappChain(ctx);
                final var proxy = new FilterChainProxy(List.of(webappChain));

                final var request = new MockHttpServletRequest("GET", SCOPED_OPERATE);
                final var response = new MockHttpServletResponse();
                proxy.doFilter(request, response, new MockFilterChain());

                assertThat(response.getStatus())
                    .as("anonymous access to scoped webapp path must redirect (302)")
                    .isEqualTo(302);
              });
    } finally {
      server.stop();
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private static OrderedSecurityFilterChainWrapper webappChain(
      final org.springframework.context.ApplicationContext ctx) {
    final var names = ctx.getBeanNamesForType(SecurityFilterChain.class);
    final var webappChainName =
        java.util.Arrays.stream(names)
            .filter(n -> n.startsWith("scopedWebappSecurityFilterChain-0-"))
            .findFirst()
            .orElseThrow(
                () -> new AssertionError("No scopedWebappSecurityFilterChain-0-* bean found"));
    return (OrderedSecurityFilterChainWrapper)
        ctx.getBean(webappChainName, SecurityFilterChain.class);
  }

  private static ScopedSecurityDescriptor buildOidcDescriptor(final OidcTestServer server)
      throws Exception {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.OIDC);
    auth.setOidc(server.oidcConfiguration("scope-client"));
    return new ScopedSecurityDescriptor(SCOPED_BASE, auth);
  }

  // ---------------------------------------------------------------------------
  // Inner configuration stubs
  // ---------------------------------------------------------------------------

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/v2/**");
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
          return Set.of("/operate/**", "/login", "/logout");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of("operate");
        }
      };
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return username -> null;
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }
}
