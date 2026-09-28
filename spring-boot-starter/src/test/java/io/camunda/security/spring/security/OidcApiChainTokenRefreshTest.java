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
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * Verifies that the primary OIDC API chain refreshes a session-authenticated caller's access token
 * the way the primary webapp chain does (camunda-security-library#662), and that it still builds in
 * a bearer-only deployment where no OAuth2 client beans exist.
 */
class OidcApiChainTokenRefreshTest {

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
                  OidcApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  OidcBeansConfiguration.class,
                  OidcWebappClientBeansConfiguration.class,
                  ScopedOidcInfrastructureConfiguration.class))
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void installsTheRefreshFilterAfterTheAuthorizationFilter() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();

          final var filters = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class).getFilters();
          final var refreshIndex = indexOf(filters, OAuth2RefreshTokenFilter.class);

          assertThat(refreshIndex)
              .as("the primary OIDC API chain must carry an OAuth2RefreshTokenFilter")
              .isNotNegative();
          assertThat(refreshIndex)
              .as("the refresh filter must run after AuthorizationFilter, as on the webapp chain")
              .isGreaterThan(indexOf(filters, AuthorizationFilter.class));
        });
  }

  @Test
  void buildsWithoutARefreshFilterWhenTheWebappChainIsDisabled() {
    runner
        .withUserConfiguration(StubJwtDecoder.class)
        .withPropertyValues("camunda.security.authentication.webapp-enabled=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx)
                  .as("a bearer-only deployment registers no OAuth2 authorized-client beans")
                  .doesNotHaveBean("authorizedClientManager");

              final var filters =
                  ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class).getFilters();

              assertThat(indexOf(filters, OAuth2RefreshTokenFilter.class))
                  .as(
                      "without a session login there is no stored token to refresh, so the chain"
                          + " must build exactly as it did before")
                  .isEqualTo(-1);
            });
  }

  private static int indexOf(
      final java.util.List<jakarta.servlet.Filter> filters, final Class<?> filterType) {
    for (int i = 0; i < filters.size(); i++) {
      if (filterType.isInstance(filters.get(i))) {
        return i;
      }
    }
    return -1;
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class StubJwtDecoder {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new JwtException("no decoder configured");
      };
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().webappPaths("/operate/**").build();
    }
  }
}
