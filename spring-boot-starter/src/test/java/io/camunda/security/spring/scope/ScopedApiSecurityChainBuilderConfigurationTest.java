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
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityConfiguration;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Regression test for the timing-fragile {@code @ConditionalOnBean(AuthFailureHandler.class)} guard
 * that was previously on the {@code scopedApiSecurityChainBuilder} bean in {@link
 * io.camunda.security.spring.security.BaseSecurityConfiguration}. When that condition evaluated
 * before {@link AuthFailureHandlerConfiguration} had registered its bean, the builder backed off
 * and the API chains that REQUIRE it ({@link OidcApiSecurityConfiguration}, {@link
 * io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration}) failed with "No
 * qualifying bean of type 'ScopedApiSecurityChainBuilder'".
 *
 * <p>Moving the builder to its own unconditional {@link ScopedApiSecurityChainBuilderConfiguration}
 * (with only {@code @ConditionalOnMissingBean}) eliminates the fragility. This test proves that the
 * builder is always available when both the OIDC API chain configuration and the failure-handler
 * configuration are imported, regardless of registration order.
 */
class ScopedApiSecurityChainBuilderConfigurationTest {

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

  /**
   * Reproduces the downstream regression: importing {@link OidcApiSecurityConfiguration} together
   * with {@link ScopedApiSecurityChainBuilderConfiguration} and {@link
   * AuthFailureHandlerConfiguration} must produce a healthy context with the OIDC filter chain
   * bean, regardless of whether the handler configuration is registered before or after the builder
   * configuration.
   */
  @Test
  void oidcApiFilterChainBeanIsCreatedWhenBuilderAndHandlerAreImported() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                ScopedApiSecurityChainBuilderConfiguration.class,
                OidcApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(OIDC_PROPERTIES)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(ScopedApiSecurityChainBuilder.class))
                  .as(
                      "ScopedApiSecurityChainBuilder must be present regardless of "
                          + "AuthFailureHandler registration order")
                  .isNotNull();
              assertThat(ctx.getBean("oidcApiSecurityFilterChain", SecurityFilterChain.class))
                  .as(
                      "oidcApiSecurityFilterChain must be created when builder is unconditionally"
                          + " available")
                  .isNotNull();
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
          return Set.of();
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of();
        }
      };
    }
  }
}
