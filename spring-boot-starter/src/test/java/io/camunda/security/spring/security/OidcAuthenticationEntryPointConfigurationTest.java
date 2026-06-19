/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class OidcAuthenticationEntryPointConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(OidcAuthenticationEntryPointConfiguration.class));

  @Test
  void defaultBeanRedirectsDirectlyToIdpWhenSingleProviderIsConfigured() throws Exception {
    runner
        .withUserConfiguration(SingleProviderRepository.class)
        .run(
            ctx -> {
              final var entryPoint = ctx.getBean(OidcAuthenticationEntryPoint.class);
              final var request = new MockHttpServletRequest();
              final var response = new MockHttpServletResponse();
              entryPoint.commence(request, response, authException());
              assertThat(response.getRedirectedUrl()).isEqualTo("/oauth2/authorization/single-idp");
            });
  }

  @Test
  void defaultBeanRedirectsToLoginPageWhenMultipleProvidersAreConfigured() throws Exception {
    runner
        .withUserConfiguration(MultiProviderRepository.class)
        .run(
            ctx -> {
              final var entryPoint = ctx.getBean(OidcAuthenticationEntryPoint.class);
              final var request = new MockHttpServletRequest();
              final var response = new MockHttpServletResponse();
              entryPoint.commence(request, response, authException());
              assertThat(response.getRedirectedUrl()).isEqualTo("/login");
            });
  }

  @Test
  void hostBeanOverridesDefaultWhenPresent() {
    runner
        .withUserConfiguration(SingleProviderRepository.class, HostEntryPoint.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(OidcAuthenticationEntryPoint.class)
                    .getBean(OidcAuthenticationEntryPoint.class)
                    .isInstanceOf(HostEntryPoint.StubEntryPoint.class));
  }

  private static AuthenticationException authException() {
    return new InsufficientAuthenticationException("unauthenticated");
  }

  private static ClientRegistration stubRegistration(final String registrationId) {
    return ClientRegistration.withRegistrationId(registrationId)
        .clientId("client-" + registrationId)
        .clientSecret("secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/sso-callback")
        .authorizationUri("http://localhost/" + registrationId + "/auth")
        .tokenUri("http://localhost/" + registrationId + "/token")
        .build();
  }

  @Configuration
  static class SingleProviderRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(stubRegistration("single-idp"));
    }
  }

  @Configuration
  static class MultiProviderRepository {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          stubRegistration("idp-a"), stubRegistration("idp-b"));
    }
  }

  @Configuration
  static class HostEntryPoint {

    @Bean
    OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
      return new StubEntryPoint();
    }

    static final class StubEntryPoint implements OidcAuthenticationEntryPoint {
      @Override
      public void commence(
          final HttpServletRequest request,
          final HttpServletResponse response,
          final AuthenticationException authException)
          throws IOException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      }
    }
  }
}
