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
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Pins that a host {@code OAuth2UserService<OidcUserRequest, OidcUser>} bean not extending {@code
 * OidcUserService} reaches the built OIDC login chain, not just that it registers.
 *
 * <p>Passes both before and after widening {@link ScopedWebappSecurityChainBuilder}'s {@code
 * oidcUserServiceProvider} field to this generic type: {@code
 * OAuth2LoginConfigurer.getOidcUserService()}'s own fallback lookup resolves the same bean either
 * way, so this pins end-to-end correctness rather than discriminating between the two lookups.
 */
class OidcWebappUserServiceWiringTest {

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

  @Test
  void hostGenericOidcUserServiceReachesTheBuiltLoginChain() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class, HostUserService.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                OidcWebappSecurityConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                OidcBeansConfiguration.class,
                OidcWebappClientBeansConfiguration.class,
                ScopedOidcInfrastructureConfiguration.class))
        .withPropertyValues(OIDC_PROPERTIES)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var chain =
                  (DefaultSecurityFilterChain)
                      ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
              final var loginFilter =
                  chain.getFilters().stream()
                      .filter(AbstractAuthenticationProcessingFilter.class::isInstance)
                      .map(AbstractAuthenticationProcessingFilter.class::cast)
                      .findFirst()
                      .orElseThrow(
                          () -> new AssertionError("No OAuth2 login filter on the built chain"));
              final var authenticationManager =
                  (AuthenticationManager)
                      ReflectionTestUtils.getField(loginFilter, "authenticationManager");
              @SuppressWarnings("unchecked")
              final List<Object> providers =
                  (List<Object>)
                      ReflectionTestUtils.getField(
                          unwrapProviderManager(authenticationManager), "providers");
              final var oidcProvider =
                  providers.stream()
                      .filter(OidcAuthorizationCodeAuthenticationProvider.class::isInstance)
                      .findFirst()
                      .orElseThrow(
                          () ->
                              new AssertionError(
                                  "No OidcAuthorizationCodeAuthenticationProvider registered"));
              final var wiredUserService =
                  ReflectionTestUtils.getField(oidcProvider, "userService");

              assertThat(wiredUserService)
                  .as(
                      "the host's generic-shape OAuth2UserService<OidcUserRequest, OidcUser> bean"
                          + " must be the service the built login chain actually calls")
                  .isSameAs(HostUserService.INSTANCE);
            });
  }

  private static ProviderManager unwrapProviderManager(final AuthenticationManager manager) {
    if (manager instanceof final ProviderManager providerManager) {
      return providerManager;
    }
    throw new AssertionError(
        "Expected the login filter's AuthenticationManager to be a ProviderManager, was: "
            + manager.getClass());
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
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class HostUserService {

    static final OAuth2UserService<OidcUserRequest, OidcUser> INSTANCE =
        request -> {
          throw new UnsupportedOperationException("stub — not invoked by this test");
        };

    @Bean
    OAuth2UserService<OidcUserRequest, OidcUser> hostOidcUserService() {
      return INSTANCE;
    }
  }
}
