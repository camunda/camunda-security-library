/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.AuthFailureHandlerAutoConfiguration;
import io.camunda.security.spring.handler.JsonProblemDetailAuthFailureHandler;
import io.camunda.security.spring.oidc.OidcBeansAutoConfiguration;
import io.camunda.security.spring.security.BaseSecurityAutoConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityAutoConfiguration;
import io.camunda.security.spring.security.BasicAuthWebappSecurityAutoConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityAutoConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityAutoConfiguration;
import io.camunda.security.spring.security.UnprotectedApiSecurityAutoConfiguration;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

class CamundaSecurityAutoConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(ObjectMapperConfig.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityAutoConfiguration.class,
                  BaseSecurityAutoConfiguration.class,
                  OidcApiSecurityAutoConfiguration.class,
                  OidcWebappSecurityAutoConfiguration.class,
                  BasicAuthApiSecurityAutoConfiguration.class,
                  BasicAuthWebappSecurityAutoConfiguration.class,
                  UnprotectedApiSecurityAutoConfiguration.class,
                  AuthFailureHandlerAutoConfiguration.class,
                  OidcBeansAutoConfiguration.class))
          .withUserConfiguration(StubPaths.class);

  @Test
  void bindsDefaultPropertiesWithoutAuthenticationMethod() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(CamundaSecurityLibraryProperties.class);
          assertThat(ctx)
              .getBean(CamundaSecurityLibraryProperties.class)
              .extracting(p -> p.getAuthentication().getMethod())
              .isNull();
        });
  }

  @Test
  void basicMethodActivatesBasicChainsAndSuppressesOidcChains() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .withUserConfiguration(StubUserDetailsService.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AuthFailureHandler.class);
              final var chains = ctx.getBeansOfType(SecurityFilterChain.class);
              assertThat(chains).isNotEmpty();
              // OIDC-specific beans must NOT be present
              assertThat(ctx).doesNotHaveBean(JwtDecoder.class);
              assertThat(ctx).doesNotHaveBean(ClientRegistrationRepository.class);
            });
  }

  @Test
  void oidcMethodActivatesOidcChainsAndSuppressesBasicChains() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
            "camunda.security.authentication.oidc.client-id=test-client",
            "camunda.security.authentication.oidc.client-secret=secret",
            "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
            "camunda.security.authentication.oidc.token-uri=http://localhost/token",
            "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
              assertThat(ctx).hasSingleBean(ClientRegistrationRepository.class);
              // SecurityFilterChain beans from base + OIDC chains
              final var chains = ctx.getBeansOfType(SecurityFilterChain.class);
              assertThat(chains).isNotEmpty();
            });
  }

  @Test
  void unprotectedApiSwapsOutProtectedApiChain() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.unprotected-api=true",
            "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
            "camunda.security.authentication.oidc.client-id=c",
            "camunda.security.authentication.oidc.client-secret=s",
            "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
            "camunda.security.authentication.oidc.token-uri=http://localhost/token",
            "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/callback")
        .run(
            ctx -> {
              // UnprotectedApiSecurityAutoConfiguration must be active
              assertThat(ctx).hasSingleBean(UnprotectedApiSecurityAutoConfiguration.class);
              // OidcApiSecurityAutoConfiguration must NOT be active (unprotected-api=true)
              assertThat(ctx).doesNotHaveBean(OidcApiSecurityAutoConfiguration.class);
            });
  }

  @Test
  void defaultAuthFailureHandlerIsJsonProblemDetail() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .getBean(AuthFailureHandler.class)
                .isInstanceOf(JsonProblemDetailAuthFailureHandler.class));
  }

  @Test
  void hostCanOverrideAuthFailureHandler() {
    runner
        .withUserConfiguration(CustomAuthFailureHandlerConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(AuthFailureHandler.class);
              assertThat(ctx)
                  .getBean(AuthFailureHandler.class)
                  .isInstanceOf(CustomAuthFailureHandlerConfig.StubAuthFailureHandler.class);
            });
  }

  @Test
  void hostCanOverrideJwtDecoder() {
    runner
        .withPropertyValues(
            "camunda.security.authentication.method=oidc",
            "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
            "camunda.security.authentication.oidc.client-id=c",
            "camunda.security.authentication.oidc.client-secret=s",
            "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
            "camunda.security.authentication.oidc.token-uri=http://localhost/token",
            "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
            "camunda.security.authentication.oidc.redirect-uri=http://localhost/callback")
        .withUserConfiguration(CustomJwtDecoderConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(JwtDecoder.class);
              assertThat(ctx)
                  .getBean(JwtDecoder.class)
                  .isInstanceOf(CustomJwtDecoderConfig.StubJwtDecoder.class);
            });
  }

  /** Stub {@link SecurityPathPort} required by all filter chain beans. */
  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort pathPort() {
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
          return Set.of("/login");
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of();
        }
      };
    }
  }

  @Configuration
  static class CustomAuthFailureHandlerConfig {

    @Bean
    AuthFailureHandler customAuthFailureHandler() {
      return new StubAuthFailureHandler();
    }

    static final class StubAuthFailureHandler implements AuthFailureHandler {
      @Override
      public void onAuthenticationFailure(
          final jakarta.servlet.http.HttpServletRequest request,
          final jakarta.servlet.http.HttpServletResponse response,
          final org.springframework.security.core.AuthenticationException exception) {}

      @Override
      public void handle(
          final jakarta.servlet.http.HttpServletRequest request,
          final jakarta.servlet.http.HttpServletResponse response,
          final org.springframework.security.access.AccessDeniedException accessDeniedException) {}

      @Override
      public void commence(
          final jakarta.servlet.http.HttpServletRequest request,
          final jakarta.servlet.http.HttpServletResponse response,
          final org.springframework.security.core.AuthenticationException authException) {}
    }
  }

  @Configuration
  static class CustomJwtDecoderConfig {

    @Bean
    JwtDecoder customJwtDecoder() {
      return new StubJwtDecoder();
    }

    static final class StubJwtDecoder implements JwtDecoder {
      @Override
      public org.springframework.security.oauth2.jwt.Jwt decode(final String token) {
        throw new UnsupportedOperationException("stub");
      }
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
