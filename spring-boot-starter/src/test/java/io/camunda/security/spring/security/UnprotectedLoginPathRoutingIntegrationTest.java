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
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * End-to-end routing for an unprotected pattern that overlaps {@code /login} (issue #710), through
 * one assembled {@link FilterChainProxy}. Asserts reachability ({@link
 * MockFilterChain#getRequest()} non-null), not status codes, since a CSRF rejection can surface as
 * 401 or 403; each negative case has a tokened control.
 */
class UnprotectedLoginPathRoutingIntegrationTest {

  private static final String USER = "alice";
  private static final String PASSWORD = "s3cret";
  private static final String UNPROTECTED_CHAIN = "unprotectedPathsSecurityFilterChain";

  private WebApplicationContextRunner runnerWith(final SecurityPathPort paths) {
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubUserDetailsPort.class)
        .withBean("securityPathPort", SecurityPathPort.class, () -> paths)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthWebappSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  /** Hub: {@code /**} API paths, no webapp paths, {@code /login} unprotected for safe methods. */
  private WebApplicationContextRunner hubShapedRunner() {
    return runnerWith(
            StubSecurityPaths.builder()
                .apiPaths("/**")
                .webappPaths()
                .unprotectedPaths("/login")
                .build())
        .withPropertyValues(
            "camunda.security.authentication.catch-all-unhandled-paths-enabled=false");
  }

  @Test
  void hubShapedGetLoginReachesAppAndCarriesCsrfToken() {
    hubShapedRunner()
        .run(
            ctx -> {
              final var proxy = proxyWithUser(ctx);

              final var response = new MockHttpServletResponse();
              final var next = new MockFilterChain();
              proxy.doFilter(new MockHttpServletRequest("GET", "/login"), response, next);

              assertThat(next.getRequest()).as("GET /login must reach the app").isNotNull();
              assertThat(response.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN))
                  .as("GET /login must issue a CSRF token for the login form")
                  .isNotNull();
            });
  }

  @Test
  void hubShapedTokenlessPostLoginDoesNotReachAppButTokenedOneDoes() {
    hubShapedRunner()
        .run(
            ctx -> {
              final var proxy = proxyWithUser(ctx);

              final var tokenlessNext = new MockFilterChain();
              proxy.doFilter(basicAuthPost("/login"), new MockHttpServletResponse(), tokenlessNext);
              assertThat(tokenlessNext.getRequest())
                  .as("a tokenless POST /login with valid credentials must not reach the app")
                  .isNull();

              // Control: same credentials plus the token from a GET reach the app.
              final var tokened = basicAuthPost("/login");
              attachCsrfFrom(proxy, "/login", tokened);
              final var tokenedNext = new MockFilterChain();
              proxy.doFilter(tokened, new MockHttpServletResponse(), tokenedNext);
              assertThat(tokenedNext.getRequest())
                  .as("a POST /login carrying the CSRF cookie and header must reach the app")
                  .isNotNull();
            });
  }

  @Test
  void webappShapedTokenlessPostLoginIsNotLoggedInButTokenedRoundTripIs() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .run(
            ctx -> {
              final var proxy = proxyWithUser(ctx);

              final var tokenlessResponse = new MockHttpServletResponse();
              final var tokenlessNext = new MockFilterChain();
              proxy.doFilter(formLoginPost(), tokenlessResponse, tokenlessNext);
              assertThat(tokenlessNext.getRequest())
                  .as("a tokenless POST /login must not pass through to the app")
                  .isNull();
              assertThat(tokenlessResponse.getStatus())
                  .as("valid credentials alone must not log in without a CSRF token")
                  .isNotEqualTo(204);
              assertThat(tokenlessResponse.getHeaders("Set-Cookie"))
                  .as("a rejected login must not commit a session")
                  .noneMatch(h -> h.startsWith(CamundaSecurityFilterChainConstants.SESSION_COOKIE));

              // Control: full round trip (GET token, POST credentials) succeeds.
              final var tokened = formLoginPost();
              attachCsrfFrom(proxy, "/login", tokened);
              final var tokenedResponse = new MockHttpServletResponse();
              proxy.doFilter(tokened, tokenedResponse, new MockFilterChain());
              assertThat(tokenedResponse.getStatus()).isEqualTo(204);
              assertThat(
                      tokenedResponse.getCookie(CamundaSecurityFilterChainConstants.SESSION_COOKIE))
                  .as("login must commit a session")
                  .isNotNull();
            });
  }

  @Test
  void webappShapedGetLoginIsServedByUnprotectedChainButPostLoginIsNot() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .run(
            ctx -> {
              final var unprotected = ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class);

              assertThat(firstMatchingChain(ctx, new MockHttpServletRequest("GET", "/login")))
                  .as("GET /login must be served by the unprotected-paths chain")
                  .isSameAs(unprotected);
              assertThat(firstMatchingChain(ctx, formLoginPost()))
                  .as("POST /login must be routed past the CSRF-disabled unprotected-paths chain")
                  .isNotNull()
                  .isNotSameAs(unprotected);
            });
  }

  /** The chain {@link FilterChainProxy} would pick: the first, in order, that matches. */
  private static SecurityFilterChain firstMatchingChain(
      final ApplicationContext ctx, final MockHttpServletRequest request) {
    return ctx.getBeanProvider(SecurityFilterChain.class)
        .orderedStream()
        .filter(chain -> chain.matches(request))
        .findFirst()
        .orElse(null);
  }

  private static FilterChainProxy proxyWithUser(final ApplicationContext ctx) {
    final var encoder = ctx.getBean(PasswordEncoder.class);
    ((ConfigurableUserDetailsPort) ctx.getBean(BasicAuthUserDetailsPort.class))
        .resolve(USER, encoder.encode(PASSWORD));
    // orderedStream() honours @Order on the @Bean factory methods, which sorting the bean
    // instances would not see.
    final var chains = ctx.getBeanProvider(SecurityFilterChain.class).orderedStream().toList();
    return new FilterChainProxy(chains);
  }

  /** GETs {@code url} through the proxy and copies the CSRF cookie and header onto {@code post}. */
  private static void attachCsrfFrom(
      final FilterChainProxy proxy, final String url, final MockHttpServletRequest post)
      throws Exception {
    final var getResponse = new MockHttpServletResponse();
    proxy.doFilter(new MockHttpServletRequest("GET", url), getResponse, new MockFilterChain());
    final var token = getResponse.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN);
    assertThat(token).as("GET " + url + " must issue a CSRF token").isNotNull();
    final Cookie[] cookies = getResponse.getCookies();
    post.setCookies(cookies);
    post.addHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN, token);
  }

  private static MockHttpServletRequest basicAuthPost(final String url) {
    final var request = new MockHttpServletRequest("POST", url);
    final var credentials = (USER + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8);
    request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials));
    return request;
  }

  private static MockHttpServletRequest formLoginPost() {
    final var request = new MockHttpServletRequest("POST", "/login");
    request.setParameter("username", USER);
    request.setParameter("password", PASSWORD);
    return request;
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      return new ConfigurableUserDetailsPort();
    }
  }

  /** Resolves whichever username/password was last configured via {@link #resolve}. */
  private static final class ConfigurableUserDetailsPort implements BasicAuthUserDetailsPort {

    private volatile CamundaUserDetails details;

    void resolve(final String username, final String encodedPassword) {
      details = new CamundaUserDetails(username, encodedPassword);
    }

    @Override
    public CamundaUserDetails loadUser(final String username) {
      final var current = details;
      return current != null && current.username().equals(username) ? current : null;
    }
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }
}
