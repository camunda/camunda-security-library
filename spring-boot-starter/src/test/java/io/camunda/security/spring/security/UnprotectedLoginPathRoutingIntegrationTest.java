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
import io.camunda.security.spring.CamundaSecurityAutoConfiguration;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.http.Cookie;
import java.util.List;
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
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * End-to-end routing for an unprotected pattern that overlaps {@code /login} (issue #710), through
 * one assembled {@link FilterChainProxy}. Mostly asserts reachability ({@link
 * MockFilterChain#getRequest()} non-null) rather than status codes, since a CSRF rejection can
 * surface as 401 or 403; every tokenless negative case has a tokened control. The Hub-shaped cases
 * model camunda-hub's OIDC wiring, which never submits {@code POST /login}.
 */
class UnprotectedLoginPathRoutingIntegrationTest {

  private static final String USER = "alice";
  private static final String PASSWORD = "s3cret";
  private static final String UNPROTECTED_CHAIN = "unprotectedPathsSecurityFilterChain";
  private static final String OIDC_API_CHAIN = "oidcApiSecurityFilterChain";
  private static final String WEBAPP_CHAIN = "basicAuthWebappSecurityFilterChain";
  private static final String GUARD_CHAIN = "unclaimedLoginGuardSecurityFilterChain";
  private static final String CATCH_ALL_CHAIN = "protectedUnhandledPathsSecurityFilterChain";

  private static final String[] HUB_PROPERTIES = {
    "camunda.security.authentication.method=oidc",
    "camunda.security.authentication.webapp-enabled=false",
    "camunda.security.authentication.catch-all-unhandled-paths-enabled=false",
    "camunda.security.authentication.oidc.jwk-set-uri=http://localhost/jwks",
    "camunda.security.authentication.oidc.client-id=test-client",
    "camunda.security.authentication.oidc.client-secret=secret",
    "camunda.security.authentication.oidc.authorization-uri=http://localhost/auth",
    "camunda.security.authentication.oidc.token-uri=http://localhost/token",
    "camunda.security.authentication.oidc.user-info-uri=http://localhost/userinfo",
    "camunda.security.authentication.oidc.redirect-uri=http://localhost/sso-callback"
  };

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

  /**
   * Mirrors camunda-hub's {@code HubSecurityPathAdapter} / {@code application-self-managed.yml}:
   * OIDC API chain on {@code /**}, no webapp chain, catch-all off; {@code /login} is an SPA route,
   * the OIDC flow runs in the browser. Activated through {@link CamundaSecurityAutoConfiguration},
   * as Hub does. Like Hub's {@code SelfManagedJwtConfiguration}, the host supplies the {@link
   * JwtDecoder}, since CSL provides none with the webapp chain disabled; it is never called because
   * no bearer token is sent. Path sets are a representative subset of Hub's (no static suffixes or
   * health paths).
   */
  private WebApplicationContextRunner hubShapedRunner() {
    final var paths =
        StubSecurityPaths.builder()
            .apiPaths("/**")
            .unprotectedPaths("/login", "/login-callback", "/logout", "/error")
            .unprotectedApiPaths(
                "/login", "/login-callback", "/logout", "/error", "/api/internal/shares/*")
            .webappPaths(
                "/login",
                "/login-callback",
                "/logout",
                "/embed/*",
                "/share/*",
                "/shares/*",
                "/maintenance")
            .build();
    return new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class)
        .withBean("securityPathPort", SecurityPathPort.class, () -> paths)
        .withBean(
            JwtDecoder.class,
            () ->
                token -> {
                  throw new BadJwtException("no bearer token is expected in these tests");
                })
        .withConfiguration(AutoConfigurations.of(CamundaSecurityAutoConfiguration.class))
        .withPropertyValues(HUB_PROPERTIES);
  }

  @Test
  void hubStartsAndServesGetLoginUnauthenticatedViaUnprotectedChain() {
    hubShapedRunner()
        .run(
            ctx -> {
              assertThat(ctx)
                  .as("Hub's wiring (catch-all off, apiPaths=/**) must start")
                  .hasNotFailed();
              final var unprotected = ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class);
              final var proxy = proxy(ctx);

              for (final var path : List.of("/login", "/login-callback")) {
                final var get = new MockHttpServletRequest("GET", path);
                assertThat(firstMatchingChain(ctx, get))
                    .as("GET " + path + " must be served by the unprotected-paths chain")
                    .isSameAs(unprotected);
                final var next = new MockFilterChain();
                proxy.doFilter(get, new MockHttpServletResponse(), next);
                assertThat(next.getRequest())
                    .as("GET " + path + " without credentials must reach the app")
                    .isNotNull();
              }
            });
  }

  @Test
  void hubStateChangingLoginIsRoutedToOidcApiChainAndRejectedWithoutCsrfToken() {
    hubShapedRunner()
        .run(
            ctx -> {
              assertThat(ctx).hasBean(GUARD_CHAIN);
              final var post = new MockHttpServletRequest("POST", "/login");
              assertThat(firstMatchingChain(ctx, post))
                  .as("POST /login must be routed to the CSRF-enforcing OIDC API chain")
                  .isSameAs(ctx.getBean(OIDC_API_CHAIN, SecurityFilterChain.class));

              final var proxy = proxy(ctx);
              final var tokenlessResponse = new MockHttpServletResponse();
              final var tokenlessNext = new MockFilterChain();
              proxy.doFilter(post, tokenlessResponse, tokenlessNext);
              assertThat(tokenlessNext.getRequest())
                  .as("a tokenless POST /login must not reach the app")
                  .isNull();

              assertThat(tokenlessResponse.getContentAsString())
                  .as("the rejection must come from CSRF enforcement")
                  .contains("CSRF token");

              // Control: the same request with a valid CSRF token reaches the app (Hub lists
              // /login in unprotectedApiPaths), so only CSRF blocked the tokenless one.
              final var tokened = new MockHttpServletRequest("POST", "/login");
              attachCsrfFrom(proxy, "/login", tokened);
              final var tokenedNext = new MockFilterChain();
              proxy.doFilter(tokened, new MockHttpServletResponse(), tokenedNext);
              assertThat(tokenedNext.getRequest())
                  .as("a tokened POST /login must pass CSRF and reach the app")
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

  /**
   * With the dispatcher servlet at {@code /app}, Spring Boot registers a {@code basePath} builder.
   * {@code POST /app/login} is then routed past the unprotected {@code /**} to the webapp chain,
   * whose CSRF matcher must use the same builder: a default-builder {@code /login} matcher misses
   * {@code /app/login}, and the unprotected {@code /**} would exempt it from CSRF.
   */
  @Test
  void webappShapedPostLoginUnderServletBasePathIsCsrfEnforced() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/**").build())
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .run(
            ctx -> {
              final var proxy = proxyWithUser(ctx);

              final var tokenlessResponse = new MockHttpServletResponse();
              final var tokenlessNext = new MockFilterChain();
              proxy.doFilter(
                  withCredentials(appRequest("POST", "/login")), tokenlessResponse, tokenlessNext);
              assertThat(tokenlessNext.getRequest())
                  .as("a tokenless POST /app/login must not pass through to the app")
                  .isNull();
              assertThat(tokenlessResponse.getStatus())
                  .as("valid credentials alone must not log in without a CSRF token")
                  .isIn(401, 403);
              assertThat(tokenlessResponse.getHeaders("Set-Cookie"))
                  .as("a rejected login must not commit a session")
                  .noneMatch(h -> h.startsWith(CamundaSecurityFilterChainConstants.SESSION_COOKIE));

              // Control: the same request with a valid token passes CSRF. (Spring Security's
              // form-login matcher ignores the host basePath builder, so it is not logged in.)
              final var tokened = withCredentials(appRequest("POST", "/login"));
              attachCsrfFrom(proxy, appRequest("GET", "/login"), tokened);
              final var tokenedResponse = new MockHttpServletResponse();
              proxy.doFilter(tokened, tokenedResponse, new MockFilterChain());
              assertThat(tokenedResponse.getStatus())
                  .as("a tokened POST /app/login must pass CSRF enforcement")
                  .isNotIn(401, 403);
            });
  }

  @Test
  void webappShapedGetLoginIsServedByUnprotectedChainButPostLoginIsNot() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .run(
            ctx -> {
              assertThat(firstMatchingChain(ctx, new MockHttpServletRequest("GET", "/login")))
                  .as("GET /login must be served by the unprotected-paths chain")
                  .isSameAs(ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class));
              assertThat(firstMatchingChain(ctx, formLoginPost()))
                  .as("POST /login must be routed to the CSRF-enforcing webapp chain")
                  .isSameAs(ctx.getBean(WEBAPP_CHAIN, SecurityFilterChain.class));
            });
  }

  @Test
  void webappShapedPostLoginIsClaimedByWebappChainBeforeTheGuardWhenCatchAllIsDisabled() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .withPropertyValues(
            "camunda.security.authentication.catch-all-unhandled-paths-enabled=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed().hasBean(GUARD_CHAIN);
              assertThat(firstMatchingChain(ctx, formLoginPost()))
                  .isSameAs(ctx.getBean(WEBAPP_CHAIN, SecurityFilterChain.class));
            });
  }

  /**
   * The webapp chain's token response filter must use the host {@code basePath} builder too:
   * anonymous {@code GET /app/login} gets a token (for the first login), {@code /app/logout} none.
   */
  @Test
  void webappShapedTokenFilterFollowsServletBasePath() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error").build())
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .run(
            ctx -> {
              final var proxy = proxy(ctx);
              final var login = new MockHttpServletResponse();
              proxy.doFilter(appRequest("GET", "/login"), login, new MockFilterChain());
              assertThat(login.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN))
                  .as("anonymous GET /app/login must issue a CSRF token")
                  .isNotNull();

              final var logout = new MockHttpServletResponse();
              proxy.doFilter(appRequest("POST", "/logout"), logout, new MockFilterChain());
              assertThat(logout.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN))
                  .as("POST /app/logout must not issue a CSRF token")
                  .isNull();
            });
  }

  @Test
  void webappShapedHeadAndOptionsLoginGetATokenAndAreNotEnforced() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .run(
            ctx -> {
              final var proxy = proxy(ctx);
              for (final var method : List.of("HEAD", "OPTIONS")) {
                final var response = new MockHttpServletResponse();
                final var next = new MockFilterChain();
                proxy.doFilter(new MockHttpServletRequest(method, "/login"), response, next);
                assertThat(next.getRequest()).as(method + " /login must reach the app").isNotNull();
                assertThat(response.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN))
                    .as(method + " /login must issue a CSRF token")
                    .isNotNull();
              }
            });
  }

  /**
   * The exclusion covers the exact {@code /login} only. Other paths under a broad pattern stay
   * fully unprotected for every method, and are never processed as a login (form login lives on the
   * webapp chain, which they do not reach).
   */
  @Test
  void webappShapedExclusionCoversExactLoginOnly() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login/**", "/log*").build())
        .run(
            ctx -> {
              final var unprotected = ctx.getBean(UNPROTECTED_CHAIN, SecurityFilterChain.class);
              assertThat(firstMatchingChain(ctx, formLoginPost()))
                  .isSameAs(ctx.getBean(WEBAPP_CHAIN, SecurityFilterChain.class));

              final var proxy = proxyWithUser(ctx);
              for (final var path : List.of("/login/", "/login/foo", "/loginx")) {
                final var post = withCredentials(new MockHttpServletRequest("POST", path));
                assertThat(firstMatchingChain(ctx, post))
                    .as("POST " + path + " stays fully unprotected")
                    .isSameAs(unprotected);
                final var response = new MockHttpServletResponse();
                final var next = new MockFilterChain();
                proxy.doFilter(post, response, next);
                assertThat(next.getRequest()).as("POST " + path + " reaches the app").isNotNull();
                assertThat(response.getCookie(CamundaSecurityFilterChainConstants.SESSION_COOKIE))
                    .as("POST " + path + " must not log in")
                    .isNull();
              }
            });
  }

  /**
   * With only the exact {@code /login} unprotected, near-misses (default parser: case-sensitive, no
   * optional trailing slash) match neither it nor the webapp chain's {@code /login}, so they reach
   * the catch-all deny chain.
   */
  @Test
  void webappShapedNearMissLoginPathsReachTheCatchAll() {
    runnerWith(StubSecurityPaths.builder().unprotectedPaths("/error", "/login").build())
        .run(
            ctx -> {
              final var proxy = proxyWithUser(ctx);
              for (final var path : List.of("/login/", "/LOGIN")) {
                final var post = withCredentials(new MockHttpServletRequest("POST", path));
                assertThat(firstMatchingChain(ctx, post))
                    .as("POST " + path)
                    .isSameAs(ctx.getBean(CATCH_ALL_CHAIN, SecurityFilterChain.class));
                final var response = new MockHttpServletResponse();
                proxy.doFilter(post, response, new MockFilterChain());
                assertThat(response.getStatus()).as("POST " + path).isEqualTo(404);
              }
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
    return proxy(ctx);
  }

  private static FilterChainProxy proxy(final ApplicationContext ctx) {
    // orderedStream() honours @Order on the @Bean factory methods, which sorting the bean
    // instances would not see.
    final var chains = ctx.getBeanProvider(SecurityFilterChain.class).orderedStream().toList();
    return new FilterChainProxy(chains);
  }

  /** GETs {@code url} through the proxy and copies the CSRF cookie and header onto {@code post}. */
  private static void attachCsrfFrom(
      final FilterChainProxy proxy, final String url, final MockHttpServletRequest post)
      throws Exception {
    attachCsrfFrom(proxy, new MockHttpServletRequest("GET", url), post);
  }

  private static void attachCsrfFrom(
      final FilterChainProxy proxy,
      final MockHttpServletRequest get,
      final MockHttpServletRequest post)
      throws Exception {
    final var getResponse = new MockHttpServletResponse();
    proxy.doFilter(get, getResponse, new MockFilterChain());
    final var token = getResponse.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN);
    assertThat(token).as("GET " + get.getRequestURI() + " must issue a CSRF token").isNotNull();
    final Cookie[] cookies = getResponse.getCookies();
    post.setCookies(cookies);
    post.addHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN, token);
  }

  private static MockHttpServletRequest formLoginPost() {
    return withCredentials(new MockHttpServletRequest("POST", "/login"));
  }

  private static MockHttpServletRequest withCredentials(final MockHttpServletRequest request) {
    request.setParameter("username", USER);
    request.setParameter("password", PASSWORD);
    return request;
  }

  /** A request dispatched to a servlet mapped at {@code /app}. */
  private static MockHttpServletRequest appRequest(final String method, final String path) {
    final var request = new MockHttpServletRequest(method, "/app" + path);
    request.setServletPath("/app");
    request.setPathInfo(path);
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
