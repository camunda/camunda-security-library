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
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfFilter;

/**
 * Regression coverage for GH-269: under multi-IdP OIDC, anonymous {@code GET /login} must reach a
 * provider-selection page rendered by Spring Security's {@code DefaultLoginPageGeneratingFilter}.
 *
 * <p>Because {@link OidcWebappSecurityConfiguration} installs a custom {@code
 * AuthenticationEntryPoint}, Spring Security's {@code DefaultLoginPageConfigurer} skips adding the
 * picker filter; {@link OidcWebappSecurityConfiguration} therefore registers it explicitly. Without
 * that explicit registration the entry point 302s users to {@code /login} and the request is then
 * handled by no filter, producing a 404.
 */
class OidcWebappLoginPickerTest {

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
  void anonymousLoginRendersProviderPickerUnderMultiIdp() throws Exception {
    runner.run(
        ctx -> {
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(java.util.List.of(chain));
          final var request = new MockHttpServletRequest("GET", "/login");
          final var response = new MockHttpServletResponse();

          proxy.doFilter(request, response, new MockFilterChain());

          assertThat(response.getStatus()).isEqualTo(200);
          final var body = response.getContentAsString();
          assertThat(body)
              .as("picker must list both client registrations")
              .contains("/oauth2/authorization/oidc")
              .contains("/oauth2/authorization/oidc-secondary");
        });
  }

  @Test
  void anonymousLoginRendersPickerEvenWithSingleRegistration() throws Exception {
    // Single-registration deployments normally redirect straight to /oauth2/authorization/{id}
    // via the entry point — users never reach /login through the normal flow. But if a user
    // navigates to /login manually (e.g. after logout, or via a bookmark), the picker filter
    // must still render the page with the single available IdP link rather than letting the
    // request fall through to a 404.
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
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
              final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
              final var proxy = new FilterChainProxy(java.util.List.of(chain));
              final var request = new MockHttpServletRequest("GET", "/login");
              final var response = new MockHttpServletResponse();

              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getStatus()).isEqualTo(200);
              assertThat(response.getContentAsString())
                  .as("picker must list the single OIDC registration")
                  .contains("/oauth2/authorization/oidc");
            });
  }

  @Test
  void hostProvidedLoginPickerFilterOverridesLibraryDefault() {
    // Hosts that ship a branded /login UI (custom client-name map, or all login types disabled
    // to fall through to a Spring MVC controller) register their own
    // DefaultLoginPageGeneratingFilter
    // bean. The library installs that bean instead of building one from the standard
    // ClientRegistrationRepository — same pattern as the other ObjectProvider hooks on this
    // chain. This test pins the override by giving the host filter a recognisable login URL
    // ("/host-login") and asserting that instance is what lands on the chain.
    runner
        .withUserConfiguration(HostLoginPickerOverride.class)
        .run(
            ctx -> {
              final var chain =
                  (DefaultSecurityFilterChain)
                      ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
              final var picker =
                  chain.getFilters().stream()
                      .filter(DefaultLoginPageGeneratingFilter.class::isInstance)
                      .map(DefaultLoginPageGeneratingFilter.class::cast)
                      .findFirst()
                      .orElseThrow();
              assertThat(picker.getLoginPageUrl())
                  .as("Host-supplied picker bean must replace the library default")
                  .isEqualTo("/host-login");
            });
  }

  @Test
  void csrfTokenResponseHeaderFilterIsRegisteredBeforeLoginPicker() {
    // Both the picker and SecurityFilterChainSupport.csrfTokenResponseHeaderFilter() anchor to
    // CsrfFilter via addFilterAfter, so they share an identical sort position in HttpSecurity's
    // filter list. Spring sorts stably, so insertion order is the tie-break. The picker
    // terminates the chain for /login responses; the CSRF header filter uses
    // HttpServletResponse.setHeader, which is a no-op once the response is committed. The CSRF
    // header filter must therefore land EARLIER in the chain than the picker. This test pins
    // that ordering so a future reorder of OidcWebappSecurityConfiguration cannot silently
    // regress it (raised by Copilot reviewer on PR #273).
    runner.run(
        ctx -> {
          final var chain =
              (DefaultSecurityFilterChain) ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var filters = chain.getFilters();

          final int csrfIndex = indexOf(filters, CsrfFilter.class);
          final int pickerIndex = indexOf(filters, DefaultLoginPageGeneratingFilter.class);
          // The CSRF response-header filter is an anonymous OncePerRequestFilter, so we identify
          // it positionally: it sits between CsrfFilter and the picker. Asserting that the
          // picker is at least two positions after CsrfFilter ensures there is room for the
          // response-header filter to run first.
          assertThat(csrfIndex).as("CsrfFilter present on chain").isGreaterThanOrEqualTo(0);
          assertThat(pickerIndex).as("Login picker present on chain").isGreaterThanOrEqualTo(0);
          assertThat(pickerIndex)
              .as(
                  "Login picker must run after csrfTokenResponseHeaderFilter so the CSRF header "
                      + "is written before the picker commits the /login response")
              .isGreaterThan(csrfIndex + 1);
        });
  }

  private static int indexOf(
      final java.util.List<jakarta.servlet.Filter> filters,
      final Class<? extends jakarta.servlet.Filter> type) {
    for (int i = 0; i < filters.size(); i++) {
      if (type.isInstance(filters.get(i))) {
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
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class HostLoginPickerOverride {

    @Bean
    DefaultLoginPageGeneratingFilter hostLoginPickerFilter() {
      final var picker = new DefaultLoginPageGeneratingFilter();
      picker.setLoginPageUrl("/host-login");
      picker.setOauth2LoginEnabled(true);
      return picker;
    }
  }

  @Configuration
  static class MultiIdpClientRegistrations {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
      return new InMemoryClientRegistrationRepository(
          stubRegistration("oidc"), stubRegistration("oidc-secondary"));
    }

    /**
     * Stub decoder: these tests exercise the security filter chain and login picker, not JWT
     * decoding. The stub registrations have no issuer-uri, so the library's default jwtDecoder
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
