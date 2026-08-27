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
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Multi-IdP regression coverage for the {@code permitAll(LOGIN_URL, LOGOUT_URL)} guard on the OIDC
 * webapp chain.
 *
 * <p>The single-IdP variants in {@link OidcWebappAuthorizationRequestResolverHookTest} cannot
 * actually exercise the redirect-loop scenario: with one client registration the delegating
 * authentication entry point resolves to {@code /oauth2/authorization/{id}} instead of {@code
 * /login}, and {@link CamundaLoginPickerFilter} additionally redirects anonymous {@code GET /login}
 * straight to that same authorization URL for single-IdP setups rather than rendering a picker
 * (ADR-0022). So those assertions hold regardless of whether {@code LOGIN_URL} is on the permit-all
 * list.
 *
 * <p>This class registers <em>two</em> client registrations so the entry-point fallback in {@link
 * OidcWebappSecurityConfiguration#oidcWebappAuthenticationEntryPoint} actually targets {@link
 * CamundaSecurityFilterChainConstants#LOGIN_URL}. That is the multi-IdP path the production fix was
 * introduced for.
 */
class OidcWebappMultiIdpRedirectLoopTest {

  private static final String OIDC_CHAIN_BEAN = "oidcWebappSecurityFilterChain";

  /**
   * Properties retain {@code authentication.method=oidc} to activate the OIDC webapp chain, but the
   * single-registration {@code ClientRegistrationRepository} produced by {@code
   * OidcBeansConfiguration} is replaced by a multi-registration bean below.
   */
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
              ObjectMapperConfig.class, StubPaths.class, MultiIdpClientRegistrations.class)
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
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void anonymousLoginRequestIsPermittedAndDoesNotLoopWithMultipleRegistrations() throws Exception {
    // With two client registrations the delegating entry point resolves to LOGIN_URL. If LOGIN_URL
    // is not on the chain's permit-all list, anonymous GET /login fails authorization, the entry
    // point fires, and the response is 302 -> /login (the loop). Permit-all on LOGIN_URL stops the
    // chain at AuthorizationFilter so the request reaches CamundaLoginPickerFilter, which renders
    // the Camunda-branded provider-selection page (200) instead.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(java.util.List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/login");
          final var response = new MockHttpServletResponse();

          // Defensive precondition: the loop assertion below is guarded by `if status == 302`,
          // which silently passes if the chain stops matching /login (e.g. LOGIN_URL drops out of
          // webappPaths()) because FilterChainProxy then falls through to the mock next chain.
          // Asserting matches() upfront makes the matcher boundary part of the test contract.
          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, new MockFilterChain());

          // The chain MUST NOT respond with the loop signature: 302 redirect to /login. Either
          // 200 (CamundaLoginPickerFilter renders the picker) or any other non-/login outcome is
          // acceptable.
          if (response.getStatus() == 302) {
            assertThat(response.getRedirectedUrl())
                .as("anonymous /login under multi-IdP must not be redirected back to /login")
                .isNotEqualTo("/login")
                .isNotEqualTo("http://localhost/login");
          }
        });
  }

  @Test
  void anonymousLogoutRequestIsPermittedAndDoesNotRedirectToLoginWithMultipleRegistrations()
      throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(java.util.List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/logout");
          final var response = new MockHttpServletResponse();

          // Defensive precondition: the loop assertion below is guarded by `if status == 302`,
          // which silently passes if the chain stops matching /logout (e.g. LOGOUT_URL drops out
          // of webappPaths()) because FilterChainProxy then falls through to the mock next chain.
          // Asserting matches() upfront makes the matcher boundary part of the test contract.
          assertThat(chain.matches(request)).isTrue();

          proxy.doFilter(request, response, new MockFilterChain());

          if (response.getStatus() == 302) {
            assertThat(response.getRedirectedUrl())
                .as("anonymous /logout under multi-IdP must not be redirected back to /login")
                .isNotEqualTo("/login")
                .isNotEqualTo("http://localhost/login");
          }
        });
  }

  @Test
  void anonymousProtectedWebappPathRedirectsToLoginUnderMultiIdp() throws Exception {
    // Locks in the resolveOauthRedirectTarget behaviour added in 1b08512: when more than one
    // client registration is present, browser navigations to a protected webapp path must be
    // redirected to LOGIN_URL so the host can render a provider-selection page. The single-IdP
    // path would instead redirect to /oauth2/authorization/{id}; this assertion is the
    // distinguishing one.
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(java.util.List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(302);
          // LoginUrlAuthenticationEntryPoint emits a relative redirect when the configured
          // login URL itself is relative (LOGIN_URL is "/login"). Both forms ("/login" and the
          // absolutised "http://localhost/login") are acceptable; the assertion guards against
          // the single-IdP path which would target /oauth2/authorization/{id} instead.
          assertThat(response.getRedirectedUrl())
              .as("multi-IdP entry point must redirect protected webapp paths to LOGIN_URL")
              .isIn("/login", "http://localhost/login");
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
      return StubSecurityPaths.builder().build();
    }
  }

  /**
   * Replaces the single-registration {@link ClientRegistrationRepository} produced by {@link
   * OidcBeansConfiguration} with a two-entry repository so the {@link
   * org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint}'s default
   * entry point resolves to {@link CamundaSecurityFilterChainConstants#LOGIN_URL}.
   */
  @Configuration
  static class MultiIdpClientRegistrations {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          stubRegistration("oidc"), stubRegistration("oidc-secondary"));
    }

    /**
     * Stub decoder: these tests exercise the security filter chain and redirect-loop behaviour, not
     * JWT decoding. The stub registrations have no issuer-uri, so the library's default jwtDecoder
     * (which requires issuer-uri for multi-provider setups) must be overridden here.
     */
    @Bean
    JwtDecoder jwtDecoder() {
      return token -> {
        throw new UnsupportedOperationException("stub — not called in this test");
      };
    }

    private static ClientRegistration stubRegistration(final String registrationId) {
      return ClientRegistration.withRegistrationId(registrationId)
          .clientId("client-" + registrationId)
          .clientSecret("secret")
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .redirectUri("http://localhost/sso-callback")
          .authorizationUri("http://localhost/" + registrationId + "/auth")
          .tokenUri("http://localhost/" + registrationId + "/token")
          .userInfoUri("http://localhost/" + registrationId + "/userinfo")
          .jwkSetUri("http://localhost/" + registrationId + "/jwks")
          .build();
    }
  }
}
