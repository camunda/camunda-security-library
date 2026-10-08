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
import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort;
import io.camunda.security.core.port.out.BasicAuthUserDetailsPort.CamundaUserDetails;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.scope.ScopedSecurityChainConfiguration;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.util.Arrays;
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
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Scoped counterpart of {@link BaseSecurityConfigurationLoginOverlapTest}: an unprotected pattern
 * covering a scoped {@code <basePath>/login} still fails startup (ADR-0032), and the scoped webapp
 * chain keeps enforcing CSRF on a tokenless {@code POST <basePath>/login}.
 */
class ScopedLoginOverlapTest {

  private static final String BASE = "/physical-tenants/t1";

  private WebApplicationContextRunner runnerWith(final String... unprotectedPaths) {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class, StubUserDetailsPort.class, SingleBasicScopeProvider.class)
        .withBean(
            "securityPathPort",
            SecurityPathPort.class,
            () -> StubSecurityPaths.builder().unprotectedPaths(unprotectedPaths).build())
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthWebappSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedSecurityChainConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  @Test
  void failsFastWhenUnprotectedPathCoversScopedLogin() {
    runnerWith("/physical-tenants/**")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining(BASE + "/login")
                    .hasMessageContaining("/physical-tenants/**")
                    .hasMessageContaining("ADR-0032"));
  }

  @Test
  void scopedWebappChainRejectsTokenlessPostToScopedLoginButAcceptsATokenedOne() {
    runnerWith("/error")
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(assertTokenlessLoginRejectedButTokenedPassesCsrf(ctx, "").getStatus())
                  .as("a tokened login with valid credentials must succeed")
                  .isEqualTo(204);
            });
  }

  /**
   * With the dispatcher servlet at {@code /app}, Spring Boot registers a {@code basePath} builder
   * and the scoped chain matches {@code /app<basePath>/login}. Its CSRF matcher must use that
   * builder too: a default-builder login matcher misses the request, so a session-less tokenless
   * {@code POST} would skip CSRF.
   */
  @Test
  void scopedWebappChainEnforcesLoginCsrfUnderHostPathPatternBuilderBasePath() {
    runnerWith("/error")
        .withBean(
            PathPatternRequestMatcher.Builder.class,
            () -> PathPatternRequestMatcher.withDefaults().basePath("/app"))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertTokenlessLoginRejectedButTokenedPassesCsrf(ctx, "/app");
            });
  }

  /**
   * Asserts a tokenless login {@code POST} is rejected and the same request with a valid token is
   * not, so the rejection is attributable to CSRF. Returns the tokened response: Spring Security's
   * form-login matcher ignores a host {@code basePath} builder, so only a root servlet logs in.
   */
  private static MockHttpServletResponse assertTokenlessLoginRejectedButTokenedPassesCsrf(
      final ApplicationContext ctx, final String servletPath) throws Exception {
    final var encoder = ctx.getBean(PasswordEncoder.class);
    ((ConfigurableUserDetailsPort) ctx.getBean(BasicAuthUserDetailsPort.class))
        .resolve("alice", encoder.encode("s3cret"));
    final var proxy =
        new FilterChainProxy(List.of(chainWithPrefix(ctx, "scopedWebappSecurityFilterChain-")));

    final var tokenless = loginPost(servletPath);
    final var tokenlessResponse = new MockHttpServletResponse();
    final var tokenlessNext = new MockFilterChain();
    proxy.doFilter(tokenless, tokenlessResponse, tokenlessNext);

    assertThat(tokenlessNext.getRequest())
        .as("a tokenless POST to the scoped login must not reach the application")
        .isNull();
    assertThat(tokenlessResponse.getStatus())
        .as("valid credentials alone must not log in without a CSRF token")
        .isIn(401, 403);
    assertThat(tokenlessResponse.getHeaders("Set-Cookie"))
        .as("a rejected login must not commit a session")
        .noneMatch(h -> h.startsWith("camunda-session"));

    // Control: the very same request with a valid token is not rejected.
    final var tokenResponse = new MockHttpServletResponse();
    proxy.doFilter(
        request("GET", servletPath, BASE + "/login"), tokenResponse, new MockFilterChain());
    final var tokened = loginPost(servletPath);
    tokened.setCookies(tokenResponse.getCookies());
    tokened.addHeader(
        CamundaSecurityFilterChainConstants.X_CSRF_TOKEN,
        tokenResponse.getHeader(CamundaSecurityFilterChainConstants.X_CSRF_TOKEN));
    final var tokenedResponse = new MockHttpServletResponse();
    proxy.doFilter(tokened, tokenedResponse, new MockFilterChain());
    assertThat(tokenedResponse.getStatus())
        .as("a tokened login must pass CSRF enforcement")
        .isNotIn(401, 403);
    return tokenedResponse;
  }

  private static MockHttpServletRequest loginPost(final String servletPath) {
    final var request = request("POST", servletPath, BASE + "/login");
    request.setParameter("username", "alice");
    request.setParameter("password", "s3cret");
    return request;
  }

  /** A request dispatched to a servlet mapped at {@code servletPath} ({@code ""} for root). */
  private static MockHttpServletRequest request(
      final String method, final String servletPath, final String path) {
    final var request = new MockHttpServletRequest(method, servletPath + path);
    if (!servletPath.isEmpty()) {
      request.setServletPath(servletPath);
      request.setPathInfo(path);
    }
    return request;
  }

  private static SecurityFilterChain chainWithPrefix(
      final ApplicationContext ctx, final String prefix) {
    final var name =
        Arrays.stream(ctx.getBeanNamesForType(SecurityFilterChain.class))
            .filter(n -> n.startsWith(prefix))
            .findFirst()
            .orElseThrow(() -> new AssertionError("No " + prefix + "* chain bean found"));
    return ctx.getBean(name, SecurityFilterChain.class);
  }

  @Configuration
  static class SingleBasicScopeProvider {

    @Bean
    CamundaSecurityScopeProvider singleBasicScope() {
      return () -> List.of(new ScopedSecurityDescriptor(BASE, new AuthenticationConfiguration()));
    }
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
