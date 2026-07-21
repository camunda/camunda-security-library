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
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.scope.ScopedApiSecurityChainBuilderConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * End-to-end coverage matching camunda-security-library#548's acceptance criteria literally: with
 * {@code webapp-enabled=false}, the API-protection chain for the active authentication method is
 * present, the webapp chain is absent, and — critically — context startup does not require any
 * {@code ClientRegistrationRepository}/{@code OAuth2AuthorizedClientManager}/{@code
 * OAuth2AuthorizedClientRepository} bean (the OIDC webapp chain's dependencies), confirming a host
 * can activate OIDC API protection without also wiring session/client-registration infrastructure.
 *
 * <p>Exercises the real {@link CamundaSecurityAutoConfiguration} umbrella (the host's actual opt-in
 * path) rather than hand-picking individual configurations, ensuring the umbrella correctly gates
 * client-registration-dependent beans on {@code webapp-enabled=true}.
 */
class WebappEnabledIntegrationTest {

  @Test
  void oidcApiChainIsPresentWebappChainIsAbsentNoClientRegistrationBeansRequired() {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, StubPaths.class, StubJwtDecoder.class, HostConfig.class)
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context)
                  .as("context must start without ClientRegistrationRepository/session beans")
                  .hasNotFailed();
              assertThat(context).hasBean("oidcApiSecurityFilterChain");
              assertThat(context).doesNotHaveBean("oidcWebappSecurityFilterChain");
              assertThat(context).doesNotHaveBean("clientRegistrationRepository");
            });
  }

  @Test
  void basicApiChainIsPresentWebappChainIsAbsent() {
    new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, StubPaths.class, StubUserDetailsService.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                BasicAuthWebappSecurityConfiguration.class,
                ScopedApiSecurityChainBuilderConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                WebAppAuthorizationFilterConfiguration.class))
        .withPropertyValues(
            "camunda.security.authentication.method=basic",
            "camunda.security.authentication.webapp-enabled=false")
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              assertThat(context).hasBean("basicAuthApiSecurityFilterChain");
              assertThat(context).doesNotHaveBean("basicAuthWebappSecurityFilterChain");
            });
  }

  @Configuration
  @ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)
  static class HostConfig {}

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
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class StubJwtDecoder {

    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
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
