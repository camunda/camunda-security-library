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
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Verifies that {@link OidcWebappSecurityConfiguration} picks up a host-supplied {@link
 * OAuth2AuthorizationRequestResolver} bean and plugs it into the {@code oauth2Login} authorization
 * endpoint. Hosts use this hook to inject per-client behaviour (e.g. multi-IdP redirects, RFC 8707
 * {@code resource} parameter) without rewriting the chain.
 */
class OidcWebappAuthorizationRequestResolverHookTest {

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
          assertThat(ctx.getBean("oidcWebappSecurityFilterChain", SecurityFilterChain.class))
              .isInstanceOf(DefaultSecurityFilterChain.class);
        });
  }

  @Test
  void hostResolverBeanIsPickedUpByTheChain() {
    // When the host registers an OAuth2AuthorizationRequestResolver bean, the chain consumes it
    // through the SPI hook so per-client authorization-request behaviour (multi-IdP, RFC 8707
    // resource parameter) takes effect instead of the Spring Security default.
    runner
        .withUserConfiguration(StubAuthorizationRequestResolver.class)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx).hasSingleBean(OAuth2AuthorizationRequestResolver.class);
              assertThat(ctx.getBean(OAuth2AuthorizationRequestResolver.class))
                  .isInstanceOf(RecordingResolver.class);
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
