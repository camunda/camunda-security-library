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
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * GH-569 regression: an OIDC webapp served under a servlet context-path must recognise its own
 * authorization-code callback.
 *
 * <p>The Camunda 8.10 chart renders {@code camunda.security.authentication.oidc.redirect-uri} as an
 * absolute URL that embeds the context-path (e.g. {@code https://host/orchestration/sso-callback}
 * under {@code server.servlet.context-path=/orchestration}). Spring's redirection-endpoint matcher
 * matches the context-path-stripped request path, so if the matcher is set to the context-prefixed
 * path {@code /orchestration/sso-callback} it can never match the context-relative callback {@code
 * /sso-callback}: the callback filter never fires, the request falls through to {@code
 * anyRequest().authenticated()}, and the entry point redirects back into the OIDC flow — an
 * infinite login loop (a regression introduced in alpha57 and absent in alpha56).
 *
 * <p>{@link ScopedWebappSecurityChainBuilder} must therefore strip the context-path so the matcher
 * stays context-relative. This test drives the whole built chain: a callback request is consumed by
 * the OAuth2 login filter (which, finding no saved authorization request, redirects to {@code "/"}
 * via {@code authorization_request_not_found}) instead of being 302'd back to {@code
 * /oauth2/authorization/oidc}, which is the loop signature.
 */
class OidcWebappContextPathRedirectLoopTest {

  private static final String OIDC_CHAIN_BEAN = "oidcWebappSecurityFilterChain";
  private static final String CONTEXT_PATH = "/orchestration";

  /**
   * A single OIDC registration (the Orchestration deployment shape) with an absolute redirect-uri
   * that embeds the {@code /orchestration} context-path, and {@code server.servlet.context-path}
   * set to match — exactly what the 8.10 chart renders for a context-path'd webapp.
   */
  private static final String[] OIDC_PROPERTIES = {
    "server.servlet.context-path=" + CONTEXT_PATH,
    "camunda.security.authentication.method=oidc",
    "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
    "camunda.security.authentication.oidc.client-id=test-client",
    "camunda.security.authentication.oidc.client-secret=secret",
    "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
    "camunda.security.authentication.oidc.token-uri=http://localhost/token",
    "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
    "camunda.security.authentication.oidc.redirect-uri=http://localhost"
        + CONTEXT_PATH
        + "/sso-callback"
  };

  private final WebApplicationContextRunner runner =
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
          .withPropertyValues(OIDC_PROPERTIES);

  @Test
  void callbackUnderContextPathIsConsumedByOidcLoginFilterAndDoesNotLoop() throws Exception {
    runner.run(
        ctx -> {
          // given a chain built for a webapp under /orchestration with a context-prefixed
          // redirect-uri
          final var chain = ctx.getBean(OIDC_CHAIN_BEAN, SecurityFilterChain.class);
          final var proxy = new FilterChainProxy(java.util.List.of(chain));

          // and the authorization-code callback as the container delivers it: request URI includes
          // the context-path, which the servlet reports separately so the context-relative path is
          // /sso-callback
          final var request = new MockHttpServletRequest("GET", CONTEXT_PATH + "/sso-callback");
          request.setContextPath(CONTEXT_PATH);
          request.setServletPath("/sso-callback");
          request.addParameter("code", "test-code");
          request.addParameter("state", "test-state");
          final var response = new MockHttpServletResponse();

          // when the callback hits the chain
          assertThat(chain.matches(request)).isTrue();
          proxy.doFilter(request, response, new MockFilterChain());

          // then the OIDC login filter claims it (no saved authorization request -> redirect to
          // "/")
          // rather than falling through to a 302 back into the OIDC flow (the loop)
          assertThat(response.getStatus()).isEqualTo(302);
          assertThat(response.getRedirectedUrl())
              .as("callback under a context-path must not be redirected back into the OIDC flow")
              .doesNotStartWith("/oauth2/authorization")
              .doesNotStartWith("http://localhost/oauth2/authorization")
              .isEqualTo("/");
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
      // The callback path must live inside webappPaths for the chain to own it (Orchestration uses
      // a catch-all); the stub default only covers /operate/**, so add /sso-callback explicitly.
      return StubSecurityPaths.builder()
          .webappPaths("/operate/**", "/sso-callback", "/login", "/logout")
          .build();
    }
  }
}
