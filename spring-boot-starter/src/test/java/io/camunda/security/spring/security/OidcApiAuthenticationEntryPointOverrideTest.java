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
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.spi.OidcApiAuthenticationEntryPoint;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Regression test for camunda-security-library#561: a host-registered {@link
 * OidcApiAuthenticationEntryPoint} bean must be honored on authentication failure instead of the
 * library's default {@code BearerTokenAuthenticationEntryPoint}, while {@link
 * OidcApiWwwAuthenticateChallengeTest} (no host bean registered) continues to pin the unmodified
 * default.
 */
class OidcApiAuthenticationEntryPointOverrideTest {

  private static final String API_CHAIN_BEAN = "oidcApiSecurityFilterChain";

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
              ObjectMapperConfig.class, StubPaths.class, HostEntryPointConfig.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  OidcApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  private final WebApplicationContextRunner runnerWithInvalidTokenDecoder =
      runner.withUserConfiguration(FailingJwtDecoderConfig.class);

  @Test
  void anonymousApiRequestIsRedirectedByHostRegisteredEntryPoint() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/api/anything");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(302);
          assertThat(response.getRedirectedUrl()).isEqualTo("/login?returnUrl=/api/anything");
        });
  }

  /**
   * Covers the second failure path {@link ScopedApiSecurityChainBuilder} wires to the same
   * host-registered entry point: a malformed/invalid bearer token handled directly by {@code
   * BearerTokenAuthenticationFilter}'s own failure handler, as opposed to the missing-credentials
   * path above (handled by {@code ExceptionTranslationFilter}).
   */
  @Test
  void invalidBearerTokenRequestIsRedirectedByHostRegisteredEntryPoint() throws Exception {
    runnerWithInvalidTokenDecoder.run(
        ctx -> {
          final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/api/anything");
          request.addHeader("Authorization", "Bearer invalid-token");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(302);
          assertThat(response.getRedirectedUrl()).isEqualTo("/login?returnUrl=/api/anything");
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
      return StubSecurityPaths.builder().webappPaths("/operate/**").build();
    }
  }

  @Configuration
  static class HostEntryPointConfig {

    @Bean
    OidcApiAuthenticationEntryPoint oidcApiAuthenticationEntryPoint() {
      return (request, response, authException) ->
          response.sendRedirect("/login?returnUrl=" + request.getRequestURI());
    }
  }

  @Configuration
  static class FailingJwtDecoderConfig {

    @Bean
    JwtDecoder jwtDecoder() {
      return (token) -> {
        throw new BadJwtException("stub decoder always rejects: " + token);
      };
    }
  }
}
