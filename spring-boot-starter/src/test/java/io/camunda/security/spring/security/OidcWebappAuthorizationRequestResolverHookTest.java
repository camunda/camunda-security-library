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
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies that {@link OidcWebappSecurityConfiguration} picks up a host-supplied {@link
 * OAuth2AuthorizationRequestResolver} bean and plugs it into the {@code oauth2Login} authorization
 * endpoint. Hosts use this hook to inject per-client behaviour (e.g. multi-IdP redirects, RFC 8707
 * {@code resource} parameter) without rewriting the chain.
 *
 * <p>Also pins the permit-all guarantee for {@code LOGIN_URL} and {@code LOGOUT_URL} on the OIDC
 * webapp chain. Without this, the delegating entry point's multi-IdP fallback (which redirects to
 * {@code /login} so the host can render a provider-selection page) re-triggers itself on the
 * anonymous {@code /login} request and loops forever.
 */
class OidcWebappAuthorizationRequestResolverHookTest {

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

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcWebappSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void chainBuildsWithoutHostResolver() {
    // Without a host bean of type OAuth2AuthorizationRequestResolver, Spring Security's default
    // resolver is used and the chain still builds — the SPI hook is opt-in.
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();
          assertThat(ctx).doesNotHaveBean(OAuth2AuthorizationRequestResolver.class);
          assertThat(ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class))
              .isInstanceOf(DefaultSecurityFilterChain.class);
        });
  }

  @Test
  void hostResolverBeanIsWiredIntoTheAuthorizationRequestRedirectFilter() {
    // When the host registers an OAuth2AuthorizationRequestResolver bean, the chain consumes it
    // through the SPI hook so per-client authorization-request behaviour (multi-IdP, RFC 8707
    // resource parameter) takes effect instead of the Spring Security default. Asserting that the
    // bean is in the context only proves it exists; this test reaches into the built chain's
    // OAuth2AuthorizationRequestRedirectFilter and confirms the resolver instance there is the
    // host bean — i.e. the chain wires it, rather than silently keeping Spring's default.
    runner
        .withUserConfiguration(StubAuthorizationRequestResolver.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
              final var hostResolver = ctx.getBean(OAuth2AuthorizationRequestResolver.class);
              final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
              final var redirectFilter =
                  filtersOf(chain).stream()
                      .filter(OAuth2AuthorizationRequestRedirectFilter.class::isInstance)
                      .map(OAuth2AuthorizationRequestRedirectFilter.class::cast)
                      .findFirst()
                      .orElseThrow(
                          () ->
                              new AssertionError(
                                  "OAuth2AuthorizationRequestRedirectFilter not present in chain"));
              final var field =
                  OAuth2AuthorizationRequestRedirectFilter.class.getDeclaredField(
                      "authorizationRequestResolver");
              field.setAccessible(true);
              assertThat(field.get(redirectFilter)).isSameAs(hostResolver);
            });
  }

  @Test
  void anonymousLoginUrlRequestIsPermittedAndDoesNotLoopBackToLogin() throws Exception {
    // Regression for the entry-point redirect loop: in multi-IdP deployments the delegating
    // AuthenticationEntryPoint redirects unauthenticated browsers to LOGIN_URL so the host can
    // render a provider-selection page. If LOGIN_URL is not permit-all on the chain itself, the
    // request to /login re-enters the chain, fails authentication again, and the entry point
    // redirects back to /login forever. The chain MUST permit anonymous /login.
    runOidcChainAndAssertNoLoginLoop("/login");
  }

  @Test
  void anonymousLogoutUrlRequestIsPermittedAndDoesNotRedirectToLogin() throws Exception {
    // Symmetric guarantee for LOGOUT_URL — kept permit-all alongside LOGIN_URL to mirror the
    // basic-auth chain shape and to keep logout reachable without a session.
    runOidcChainAndAssertNoLoginLoop("/logout");
  }

  private void runOidcChainAndAssertNoLoginLoop(final String path) {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", path);
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          // The chain must not short-circuit anonymous /login or /logout with a 302 to /login —
          // that's the loop signature the permit-all guards against.
          if (response.getStatus() == 302) {
            assertThat(response.getRedirectedUrl())
                .as("anonymous %s must not be redirected back to /login by the chain", path)
                .isNotEqualTo("/login")
                .isNotEqualTo("http://localhost/login");
          }
        });
  }

  private static List<Filter> filtersOf(final SecurityFilterChain chain) {
    return ((DefaultSecurityFilterChain) chain).getFilters();
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
  static class StubAuthorizationRequestResolver {

    @Bean
    OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver() {
      return new RecordingResolver();
    }
  }

  /**
   * Distinguishable host implementation. The chain instantiates Spring Security's default resolver
   * internally even when a host bean is present, so the test asserts identity against this concrete
   * class rather than the {@link OAuth2AuthorizationRequestResolver} interface.
   */
  static final class RecordingResolver implements OAuth2AuthorizationRequestResolver {
    @Override
    public OAuth2AuthorizationRequest resolve(final HttpServletRequest request) {
      return null;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(
        final HttpServletRequest request, final String clientRegistrationId) {
      return null;
    }
  }
}
