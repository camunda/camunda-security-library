/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Covers {@code BaseSecurityConfiguration}'s handling of an unprotected pattern that overlaps the
 * unscoped {@code /login} (ADR-0032, issue #710). Scoped overlaps are covered by {@link
 * ScopedLoginOverlapTest}.
 */
class BaseSecurityConfigurationLoginOverlapTest {

  private static final String CHAIN = "unprotectedPathsSecurityFilterChain";
  private static final String GUARD = "unclaimedLoginGuardSecurityFilterChain";
  private static final String TOKEN_HEADER = CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

  private static final String CATCH_ALL_DISABLED =
      "camunda.security.authentication.catch-all-unhandled-paths-enabled=false";

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, BaseSecurityConfiguration.class));

  private WebApplicationContextRunner runnerWith(final String... unprotectedPaths) {
    return runner.withBean(
        SecurityPathPort.class,
        () -> StubSecurityPaths.builder().unprotectedPaths(unprotectedPaths).build());
  }

  private WebApplicationContextRunner runnerWithPaths(final StubSecurityPaths.Builder paths) {
    return runner.withBean(SecurityPathPort.class, paths::build);
  }

  private static boolean matches(
      final SecurityFilterChain chain, final String method, final String uri) {
    return chain.matches(new MockHttpServletRequest(method, uri));
  }

  @Test
  void startsNormallyWhenUnprotectedPathsDoNotOverlapLogin() {
    runnerWith("/error", "/logs/**").run(ctx -> assertThat(ctx).hasNotFailed().hasBean(CHAIN));
  }

  @Test
  void servesSafeMethodsButNotStateChangingMethodsOnExactLogin() {
    runnerWith("/login")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              for (final var method : List.of("GET", "HEAD", "TRACE", "OPTIONS")) {
                assertThat(matches(chain, method, "/login")).as(method).isTrue();
              }
              for (final var method : List.of("POST", "PUT", "DELETE")) {
                assertThat(matches(chain, method, "/login")).as(method).isFalse();
              }
            });
  }

  @Test
  void servesSafeMethodsButNotStateChangingMethodsOnWildcardOverlappingLogin() {
    runnerWith("/log*")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              for (final var method : List.of("GET", "HEAD", "TRACE", "OPTIONS")) {
                assertThat(matches(chain, method, "/login")).as(method).isTrue();
              }
              for (final var method : List.of("POST", "PUT", "DELETE")) {
                assertThat(matches(chain, method, "/login")).as(method).isFalse();
              }
            });
  }

  /**
   * Spring Boot registers a {@link PathPatternRequestMatcher.Builder} with {@code
   * basePath(spring.mvc.servlet.path)} when the dispatcher servlet is not mapped to {@code /}. Both
   * the unprotected-paths matcher and the state-changing {@code /login} exclusion must honour it:
   * fixing only the former would let {@code POST /app/login} into the CSRF-disabled chain.
   */
  @Test
  void honoursHostPathPatternBuilderBasePathForPathsAndLoginExclusion() {
    runnerWith("/error", "/login")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              assertThat(chain.matches(servletRequest("GET", "/app/error"))).isTrue();
              assertThat(chain.matches(servletRequest("POST", "/app/error"))).isTrue();
              for (final var method : List.of("GET", "HEAD", "TRACE", "OPTIONS")) {
                assertThat(chain.matches(servletRequest(method, "/app/login"))).as(method).isTrue();
              }
              for (final var method : List.of("POST", "PUT", "DELETE")) {
                assertThat(chain.matches(servletRequest(method, "/app/login")))
                    .as(method)
                    .isFalse();
              }
            });
  }

  /** A request dispatched to a servlet mapped at {@code /app}. */
  private static MockHttpServletRequest servletRequest(final String method, final String uri) {
    final var request = new MockHttpServletRequest(method, uri);
    request.setServletPath("/app");
    request.setPathInfo(uri.substring("/app".length()));
    return request;
  }

  @Test
  void stillServesStateChangingRequestsToOtherUnprotectedPaths() {
    runnerWith("/login", "/error")
        .run(
            ctx -> {
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              assertThat(matches(chain, "POST", "/error")).isTrue();
            });
  }

  @Test
  void issuesCsrfTokenOnGetLoginWhenUnprotectedPathsOverlapLogin() {
    runnerWith("/login")
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(List.of(ctx.getBean(CHAIN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(
                  new MockHttpServletRequest("GET", "/login"), response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNotNull();
              assertThat(response.getCookie(TOKEN_HEADER)).isNotNull();
            });
  }

  @Test
  void issuesCsrfTokenOnGetLoginUnderHostPathPatternBuilderBasePath() {
    runnerWith("/login")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(List.of(ctx.getBean(CHAIN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(servletRequest("GET", "/app/login"), response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNotNull();
              assertThat(response.getCookie(TOKEN_HEADER)).isNotNull();
            });
  }

  /**
   * A host builder with a case-insensitive parser routes {@code GET /login} into the unprotected
   * chain via {@code /LOGIN}, although the default-parser overlap check finds no overlap. Token
   * issuance must not depend on that check.
   */
  @Test
  void issuesCsrfTokenOnGetLoginWhenHostParserMatchesLoginButDefaultParserDoesNot() {
    final var parser = new PathPatternParser();
    parser.setCaseSensitive(false);
    runnerWith("/LOGIN")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withPathPatternParser(parser))
        .run(
            ctx -> {
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              assertThat(matches(chain, "GET", "/login")).isTrue();
              assertThat(matches(chain, "POST", "/login")).isFalse();

              final var proxy = new FilterChainProxy(List.of(chain));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(
                  new MockHttpServletRequest("GET", "/login"), response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNotNull();
              assertThat(response.getCookie(TOKEN_HEADER)).isNotNull();
            });
  }

  @Test
  void writesNoTokenOnAuthenticatedGetOfOtherUnprotectedPath() {
    runnerWith("/login", "/error")
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(List.of(ctx.getBean(CHAIN, SecurityFilterChain.class)));
              final var request = new MockHttpServletRequest("GET", "/error");
              request.setSession(authenticatedSession());
              final var response = new MockHttpServletResponse();
              proxy.doFilter(request, response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNull();
              assertThat(response.getCookie(TOKEN_HEADER)).isNull();
            });
  }

  private static MockHttpSession authenticatedSession() {
    final var context = new SecurityContextImpl();
    context.setAuthentication(
        new UsernamePasswordAuthenticationToken(
            "demo", "n/a", List.of(new SimpleGrantedAuthority("ROLE_USER"))));
    final var session = new MockHttpSession();
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    return session;
  }

  @Test
  void issuesNoCsrfTokenWhenUnprotectedPathsDoNotOverlapLogin() {
    runnerWith("/error", "/logs/**")
        .run(
            ctx -> {
              final var proxy =
                  new FilterChainProxy(List.of(ctx.getBean(CHAIN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(
                  new MockHttpServletRequest("GET", "/error"), response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNull();
              assertThat(response.getCookie(TOKEN_HEADER)).isNull();
            });
  }

  @Test
  void startsAndWritesNoTokenWhenCsrfIsDisabled() {
    runnerWith("/login")
        .withPropertyValues("camunda.security.csrf.enabled=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var proxy =
                  new FilterChainProxy(List.of(ctx.getBean(CHAIN, SecurityFilterChain.class)));
              final var response = new MockHttpServletResponse();
              proxy.doFilter(
                  new MockHttpServletRequest("GET", "/login"), response, new MockFilterChain());

              assertThat(response.getHeader(TOKEN_HEADER)).isNull();
            });
  }

  @Test
  void emptyUnprotectedPathsYieldAChainThatMatchesNothing() {
    runnerWith()
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
              assertThat(matches(chain, "GET", "/error")).isFalse();
              assertThat(matches(chain, "GET", "/login")).isFalse();
            });
  }

  @Test
  void logsStateChangingLoginRoutingAndNoWarningByDefault() {
    final var events = captureLogs(() -> runnerWith("/login").run(ctx -> {}));

    assertThat(messages(events, Level.INFO))
        .anyMatch(m -> m.contains("'/login'") && m.contains("enforces CSRF"));
    assertThat(messages(events, Level.WARN)).isEmpty();
  }

  /** With CSRF disabled there is nothing to enforce, so {@code /login} is not rerouted (1.0.x). */
  @Test
  void servesAllMethodsOnLoginAndLogsNothingWhenCsrfIsDisabled() {
    final var events =
        captureLogs(
            () ->
                runnerWith("/login")
                    .withPropertyValues("camunda.security.csrf.enabled=false")
                    .run(
                        ctx -> {
                          final var chain = ctx.getBean(CHAIN, SecurityFilterChain.class);
                          for (final var method : List.of("GET", "POST", "PUT", "DELETE")) {
                            assertThat(matches(chain, method, "/login")).as(method).isTrue();
                          }
                        }));

    assertThat(messages(events, Level.INFO)).noneMatch(m -> m.contains("'/login'"));
  }

  @Test
  void guardsStateChangingLoginThatNoChainClaimsWhenCatchAllIsDisabled() {
    final var events =
        captureLogs(
            () ->
                runnerWithPaths(
                        StubSecurityPaths.builder()
                            .unprotectedPaths("/log*")
                            .apiPaths("/api/**")
                            .webappPaths("/operate/**"))
                    .withPropertyValues(CATCH_ALL_DISABLED)
                    .run(
                        ctx -> {
                          assertThat(ctx).hasNotFailed();
                          final var unprotected = ctx.getBean(CHAIN, SecurityFilterChain.class);
                          final var guard = ctx.getBean(GUARD, SecurityFilterChain.class);
                          for (final var method : List.of("POST", "PUT", "DELETE")) {
                            assertThat(matches(guard, method, "/login")).as(method).isTrue();
                          }
                          assertThat(matches(guard, "GET", "/login")).isFalse();
                          assertThat(matches(guard, "POST", "/logs")).isFalse();
                          assertThat(matches(unprotected, "POST", "/logs")).isTrue();

                          final var response = new MockHttpServletResponse();
                          final var next = new MockFilterChain();
                          new FilterChainProxy(List.of(unprotected, guard))
                              .doFilter(
                                  new MockHttpServletRequest("POST", "/login"), response, next);
                          assertThat(next.getRequest()).isNull();
                          assertThat(response.getStatus()).isEqualTo(404);
                        }));

    assertThat(messages(events, Level.INFO)).anyMatch(m -> m.contains(GUARD));
  }

  @Test
  void guardMatchesNothingWhenUnprotectedPathsDoNotOverlapLogin() {
    runnerWith("/error")
        .withPropertyValues(CATCH_ALL_DISABLED)
        .run(
            ctx -> {
              final var guard = ctx.getBean(GUARD, SecurityFilterChain.class);
              assertThat(matches(guard, "POST", "/login")).isFalse();
              assertThat(matches(guard, "POST", "/error")).isFalse();
            });
  }

  /**
   * A host builder with a case-insensitive parser routes {@code POST /login} off the unprotected
   * chain via {@code /LOGIN}, although the default parser sees no overlap. The guard is built with
   * the same builder, so it still claims the request.
   */
  @Test
  void guardsStateChangingLoginWhenHostParserMatchesLoginButDefaultParserDoesNot() {
    final var parser = new PathPatternParser();
    parser.setCaseSensitive(false);
    runnerWith("/LOGIN")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withPathPatternParser(parser))
        .withPropertyValues(CATCH_ALL_DISABLED)
        .run(
            ctx -> {
              assertThat(matches(ctx.getBean(CHAIN, SecurityFilterChain.class), "POST", "/login"))
                  .isFalse();
              assertThat(matches(ctx.getBean(GUARD, SecurityFilterChain.class), "POST", "/login"))
                  .isTrue();
            });
  }

  @Test
  void guardFollowsHostPathPatternBuilderBasePath() {
    runnerWith("/**")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .withPropertyValues(CATCH_ALL_DISABLED)
        .run(
            ctx -> {
              final var post = servletRequest("POST", "/app/login");
              assertThat(ctx.getBean(CHAIN, SecurityFilterChain.class).matches(post)).isFalse();
              assertThat(ctx.getBean(GUARD, SecurityFilterChain.class).matches(post)).isTrue();
            });
  }

  @Test
  void startsWithCatchAllDisabledWhenCsrfIsDisabledAndKeepsLoginOnTheUnprotectedChain() {
    runnerWithPaths(
            StubSecurityPaths.builder()
                .unprotectedPaths("/log*")
                .apiPaths("/api/**")
                .webappPaths("/operate/**"))
        .withPropertyValues(CATCH_ALL_DISABLED, "camunda.security.csrf.enabled=false")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(matches(ctx.getBean(CHAIN, SecurityFilterChain.class), "POST", "/login"))
                  .as("POST /login stays on the unprotected chain")
                  .isTrue();
              assertThat(matches(ctx.getBean(GUARD, SecurityFilterChain.class), "POST", "/login"))
                  .isFalse();
            });
  }

  @Test
  void installsNoGuardWhileTheCatchAllIsEnabled() {
    runnerWith("/login").run(ctx -> assertThat(ctx).hasNotFailed().doesNotHaveBean(GUARD));
  }

  /**
   * The guard takes the catch-all's slot: a host chain ordered after it starts fine but never sees
   * the guarded requests, so a chain that should serve them must be ordered before it.
   */
  @Test
  void hostChainOrderedAfterTheGuardDoesNotSeeGuardedLogin() {
    runnerWith("/login")
        .withUserConfiguration(LateHostChain.class)
        .withPropertyValues(CATCH_ALL_DISABLED)
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              final var post = new MockHttpServletRequest("POST", "/login");
              final var first =
                  ctx.getBeanProvider(SecurityFilterChain.class)
                      .orderedStream()
                      .filter(chain -> chain.matches(post))
                      .findFirst()
                      .orElseThrow();
              assertThat(first).isSameAs(ctx.getBean(GUARD, SecurityFilterChain.class));
            });
  }

  @Configuration
  static class LateHostChain {

    @Bean
    @Order(10)
    SecurityFilterChain lateHostChain(final HttpSecurity http) throws Exception {
      return http.securityMatcher("/**")
          .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
          .build();
    }
  }

  private static List<ILoggingEvent> captureLogs(final Runnable action) {
    final var logger = (Logger) LoggerFactory.getLogger(BaseSecurityConfiguration.class);
    final var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    try {
      action.run();
    } finally {
      logger.detachAppender(appender);
    }
    return appender.list;
  }

  private static List<String> messages(final List<ILoggingEvent> events, final Level level) {
    return events.stream()
        .filter(event -> event.getLevel() == level)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }
}
