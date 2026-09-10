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
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.spi.WebAppProviderPort;
import io.camunda.security.spring.testsupport.PermissiveAuthorizationCheckPort;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import jakarta.servlet.Filter;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Behavioral coverage for the permit-all request authorization introduced for the basic-auth webapp
 * chain (see {@link BasicAuthWebappSecurityConfiguration}). The chain matcher is permissive at the
 * request-authorization level — anonymous browser requests must not be redirected or 401'd by the
 * security chain — but the post-authentication filters ({@link WebAppAuthorizationCheckFilter},
 * {@link io.camunda.security.spring.filter.AdminUserCheckFilter}) must still be wired in so that
 * authenticated requests are still subject to per-web-app authorization.
 *
 * <p>One path is a deliberate exception to "permit-all": the session activity-heartbeat endpoint
 * (see {@link io.camunda.security.spring.filter.SessionHeartbeatFilter}) has no downstream
 * authorization filter of its own to fall back on, so it carries an explicit {@code
 * .authenticated()} rule ahead of the chain's {@code permitAll()} catch-all (ADR-0020).
 */
class BasicAuthWebappPermitAllChainTest {

  private static final String BASIC_CHAIN_BEAN = "basicAuthWebappSecurityFilterChain";

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
                  WebAppAuthorizationFilterConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=basic");

  @Test
  void anonymousWebappRequestIsPermittedByTheChain() throws Exception {
    // The 86cd7a1 contract: an unauthenticated browser GET to a webapp path must traverse the
    // chain without being rejected (no 401, no redirect-to-login from the matcher level). The SPA
    // shell itself handles the login UX client-side against LOGIN_URL.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
          final var response = new MockHttpServletResponse();
          final var nextChain = new MockFilterChain();

          // Defensive precondition: if the chain's securityMatcher ever stops matching this path
          // (e.g. someone drops "/operate/**" from webappPaths()), FilterChainProxy would fall
          // through to nextChain and the request would appear successful for the wrong reason.
          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, nextChain);

          // permit-all means the chain hands off to the next filter (i.e. downstream MVC) rather
          // than short-circuiting with an auth challenge or redirect.
          assertThat(nextChain.getRequest()).isNotNull();
          assertThat(response.getStatus()).isEqualTo(200);
          assertThat(response.getRedirectedUrl()).isNull();
        });
  }

  @Test
  void loginUrlReachesTheFormLoginConfigurer() throws Exception {
    // The login URL is mapped by the form-login configurer; an anonymous POST against it must be
    // accepted by the chain (rather than rejected at the matcher level) so credential validation
    // happens. With invalid credentials and a stub UserDetailsService, the form-login failure
    // handler runs — the assertion is that the chain itself does not 404 / 401 the request before
    // the configurer sees it.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("POST", "/login");
          request.setParameter("username", "user");
          request.setParameter("password", "wrong");
          final var response = new MockHttpServletResponse();
          final var nextChain = new MockFilterChain();

          // Defensive precondition: if "/login" ever drops out of webappPaths(), the chain would
          // not match and FilterChainProxy would silently fall through to nextChain, masking the
          // form-login configurer behaviour this test asserts.
          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, nextChain);

          // The form-login configurer terminates the chain on credential check (success or
          // failure), so the next filter is not invoked. The chain itself accepted the request.
          assertThat(nextChain.getRequest()).isNull();
        });
  }

  @Test
  void heartbeatEndpointRequiresAuthenticationUnlikeEveryOtherPathOnThisChain() throws Exception {
    // Every other path on this chain is permitAll at the authorizeHttpRequests layer (see
    // anonymousWebappRequestIsPermittedByTheChain above) — business paths are gated downstream by
    // WebAppAuthorizationCheckFilter/AdminUserCheckFilter instead. The heartbeat endpoint has no
    // equivalent downstream gate, so it must be the one path on this chain that is NOT permitAll.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("POST", "/session/heartbeat");
          final var response = new MockHttpServletResponse();
          final var nextChain = new MockFilterChain();

          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, nextChain);

          assertThat(nextChain.getRequest())
              .as("must not reach SessionHeartbeatFilter or any downstream filter unauthenticated")
              .isNull();
          assertThat(response.getStatus())
              .as("the chain's AuthenticationEntryPoint must reject the anonymous request")
              .isEqualTo(401);
        });
  }

  @Test
  void postAuthenticationFiltersAreRegisteredEvenWithPermitAllMatcher() {
    // Structural regression boundary for the permit-all change: relaxing the request matcher must
    // not silently remove the post-authentication filters from the chain. WebAppAuthorizationCheck
    // is the post-login authorization invariant — without it, a logged-in user could reach any
    // permitted webapp path. Wiring a behavioral assertion against a real authenticated principal
    // requires more collaborators than the chain owns; the structural assertion paired with the
    // unit-level coverage of WebAppAuthorizationCheckFilter is the documented fallback.
    runner
        .withUserConfiguration(StubAuthorizationCheckPort.class)
        .withUserConfiguration(StubWebAppProvider.class)
        .withUserConfiguration(StubAuthenticationProvider.class)
        .run(
            ctx -> {
              final var chain = ctx.getBean(BASIC_CHAIN_BEAN, SecurityFilterChain.class);
              assertThat(filtersOf(chain))
                  .anySatisfy(
                      f -> assertThat(f).isInstanceOf(WebAppAuthorizationCheckFilter.class));
            });
  }

  private static List<Filter> filtersOf(final SecurityFilterChain chain) {
    return ((DefaultSecurityFilterChain) chain).getFilters();
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
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
