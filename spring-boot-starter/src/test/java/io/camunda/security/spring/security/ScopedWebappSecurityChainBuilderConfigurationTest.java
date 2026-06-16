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
import io.camunda.security.spring.CamundaSecurityAutoConfiguration;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Verifies that {@link ScopedWebappSecurityChainBuilder} and {@link
 * OAuth2AuthorizedClientManagerFactory} beans are registered by the umbrella auto-configuration,
 * and that a host-supplied builder takes precedence via {@code @ConditionalOnMissingBean}.
 */
class ScopedWebappSecurityChainBuilderConfigurationTest {

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

  @Test
  void scopedWebappSecurityChainBuilderBeanIsPresentWhenAutoConfigurationRuns() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(AutoConfigurations.of(CamundaSecurityAutoConfiguration.class))
        .withPropertyValues(OIDC_PROPERTIES)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(ScopedWebappSecurityChainBuilder.class))
                  .as("ScopedWebappSecurityChainBuilder must be provided by auto-configuration")
                  .isNotNull();
              assertThat(ctx.getBean(OAuth2AuthorizedClientManagerFactory.class))
                  .as("OAuth2AuthorizedClientManagerFactory must be provided by auto-configuration")
                  .isNotNull();
            });
  }

  @Test
  void hostCanOverrideScopedWebappSecurityChainBuilder() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, CustomBuilder.class)
        .withConfiguration(AutoConfigurations.of(CamundaSecurityAutoConfiguration.class))
        .withPropertyValues(OIDC_PROPERTIES)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(ScopedWebappSecurityChainBuilder.class))
                  .isSameAs(ctx.getBean("customScopedWebappBuilder"));
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

  @Configuration
  static class CustomBuilder {

    @Bean(name = "customScopedWebappBuilder")
    ScopedWebappSecurityChainBuilder customScopedWebappBuilder() {
      return new ScopedWebappSecurityChainBuilder();
    }
  }
}
