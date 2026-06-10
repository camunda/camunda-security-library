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
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Regression test for the fix in commit {@code e72b641} (preserve {@code WWW-Authenticate} header
 * on OIDC API chain 401 responses). Previously, registering the host {@link
 * io.camunda.security.spring.handler.AuthFailureHandler} as the {@code authenticationEntryPoint}
 * suppressed Spring Security's {@code BearerTokenAuthenticationEntryPoint}, swallowing the standard
 * RFC 6750 {@code WWW-Authenticate: Bearer} challenge (and the RFC 9728 {@code resource_metadata}
 * link) on anonymous 401 responses. Dropping the entry-point override restored Spring's bearer
 * challenge — the assertion below pins that contract.
 */
class OidcApiWwwAuthenticateChallengeTest {

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
          .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  // No manual ScopedApiSecurityChainBuilderConfiguration import: it is @Imported by
                  // OidcApiSecurityConfiguration, so the individual-import path must be
                  // self-contained.
                  OidcApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void anonymousApiRequestReturns401WithBearerWwwAuthenticateHeader() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/api/anything");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(401);
          final var challenge = response.getHeader(HttpHeaders.WWW_AUTHENTICATE);
          assertThat(challenge)
              .as(
                  "Spring's BearerTokenAuthenticationEntryPoint must emit the RFC 6750"
                      + " bearer challenge on anonymous 401s")
              .isNotNull()
              .startsWith("Bearer");
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
          return Set.of("/operate/**");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of("operate");
        }
      };
    }
  }
}
