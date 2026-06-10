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
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
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
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Pins the contract that the OIDC <em>webapp</em> chain does not authenticate JWT bearer tokens.
 *
 * <p>Bearer/JWT access (client credentials, direct API access) is the dedicated API chain's
 * responsibility — see {@link OidcApiSecurityConfiguration}. The webapp chain authenticates users
 * interactively via {@code oauth2Login} and serves them from the resulting session. A bearer token
 * presented to a webapp path must therefore <em>not</em> authenticate; it falls through to the
 * delegating entry point, which returns 401 for {@code Authorization}-bearing requests (rather than
 * a browser-oriented 302 redirect to the IdP).
 *
 * <p>The single-registration {@link ClientRegistrationRepository} makes the browser-navigation case
 * resolve to {@code /oauth2/authorization/oidc}, distinguishing it from the 401 returned to a
 * bearer request.
 */
class OidcWebappBearerTokenRejectedTest {

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
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, SingleIdpClientRegistration.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcWebappSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void webappChainHasNoBearerTokenAuthenticationFilter() {
    // Structural regression guard: removing oauth2ResourceServer must keep the
    // BearerTokenAuthenticationFilter off the webapp chain. If a future change re-adds the resource
    // server, this assertion fails immediately rather than silently re-enabling bearer auth on the
    // webapp paths.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          assertThat(chain.getFilters())
              .as("webapp chain must not install a bearer-token authentication filter")
              .noneMatch(BearerTokenAuthenticationFilter.class::isInstance);
        });
  }

  @Test
  void bearerTokenOnProtectedWebappPathIsRejectedWith401() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
          request.addHeader("Authorization", "Bearer some-opaque-or-jwt-token");
          final var response = new MockHttpServletResponse();

          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, new MockFilterChain());

          // The bearer token is not authenticated (no resource server). The delegating entry point
          // sees the Authorization header and returns 401 — not a 302 redirect to the IdP.
          assertThat(response.getStatus())
              .as("bearer token on a webapp path must not authenticate; expect 401")
              .isEqualTo(401);
          assertThat(response.getRedirectedUrl())
              .as("a bearer request must not be redirected to the IdP login")
              .isNull();
        });
  }

  @Test
  void browserNavigationToProtectedWebappPathStillRedirectsToIdp() throws Exception {
    // Counterpart to the bearer case: a browser navigation (no Authorization header) on the same
    // protected path is still redirected to the IdP authorization endpoint, confirming the
    // delegating entry point's default branch is unchanged.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(302);
          assertThat(response.getRedirectedUrl())
              .as("single-IdP browser navigation must redirect to the authorization endpoint")
              .isIn("/oauth2/authorization/oidc", "http://localhost/oauth2/authorization/oidc");
        });
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

  /**
   * Single-registration repository so the delegating entry point's default branch resolves to
   * {@code /oauth2/authorization/oidc}. The stub {@link JwtDecoder} keeps the context hermetic — it
   * is never invoked because the webapp chain no longer wires a resource server.
   */
  @Configuration
  static class SingleIdpClientRegistration {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(stubRegistration("oidc"));
    }

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }

    private static ClientRegistration stubRegistration(final String registrationId) {
      return ClientRegistration.withRegistrationId(registrationId)
          .clientId("client-" + registrationId)
          .clientSecret("secret")
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri("http://localhost/sso-callback")
          .authorizationUri("http://localhost/" + registrationId + "/auth")
          .tokenUri("http://localhost/" + registrationId + "/token")
          .userInfoUri("http://localhost/" + registrationId + "/userinfo")
          .jwkSetUri("http://localhost/" + registrationId + "/jwks")
          .build();
    }
  }
}
