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
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.session.WebSessionTestAccess;
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies ADR-0012: the default (non-scoped) webapp and API chains share one explicit {@link
 * SessionRepositoryFilter} instance, installed the same way a physical-tenant scope's chains share
 * theirs — no separately registered global {@code @EnableSpringHttpSession} filter.
 */
class DefaultSessionFilterChainIntegrationTest {

  private static final String WEBAPP_CHAIN_BEAN = "basicAuthWebappSecurityFilterChain";
  private static final String API_CHAIN_BEAN = "basicAuthApiSecurityFilterChain";
  private static final String COOKIE_NAME = CamundaSecurityFilterChainConstants.SESSION_COOKIE;

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withUserConfiguration(
              ObjectMapperConfig.class, StubPaths.class, StubUserDetailsPort.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  BaseSecurityConfiguration.class,
                  BasicAuthWebappSecurityConfiguration.class,
                  BasicAuthApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  UserConfiguration.class))
          .withPropertyValues("camunda.security.authentication.method=basic");

  @Test
  void webappAndApiChainsShareTheSameDefaultSessionRepositoryFilter() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();
          assertThat(ctx).hasSingleBean(SessionRepositoryFilter.class);

          final var webappChain = ctx.getBean(WEBAPP_CHAIN_BEAN, SecurityFilterChain.class);
          final var apiChain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);

          assertThat(sessionRepositoryFilter(apiChain))
              .as(
                  "the default webapp and API chains must share the exact same"
                      + " SessionRepositoryFilter instance, mirroring per-scope chains")
              .isSameAs(sessionRepositoryFilter(webappChain));
        });
  }

  @Test
  void sessionMintedOnWebappChainAuthenticatesTheApiChain() throws Exception {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();

          final var webappChain = ctx.getBean(WEBAPP_CHAIN_BEAN, SecurityFilterChain.class);
          final var apiChain = ctx.getBean(API_CHAIN_BEAN, SecurityFilterChain.class);

          // given — seed an authenticated session via the webapp chain's session store
          final var repo = sessionRepository(sessionRepositoryFilter(webappChain));
          final var session = repo.createSession();
          final var principal =
              new UsernamePasswordAuthenticationToken(
                  "alice", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
          session.setAttribute(
              HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
              new SecurityContextImpl(principal));
          repo.save(session);

          // when — present the webapp-minted cookie to the API chain (no bearer token)
          final var proxy = new FilterChainProxy(List.of(apiChain));
          final var request = new MockHttpServletRequest("GET", "/api/resource");
          request.setCookies(
              new jakarta.servlet.http.Cookie(COOKIE_NAME, encodedCookieValue(session.getId())));
          final var response = new MockHttpServletResponse();
          final var next = new MockFilterChain();
          proxy.doFilter(request, response, next);

          // then — the single shared filter honours the cookie: reaches downstream with 200
          assertThat(response.getStatus())
              .as(
                  "a session minted via the default webapp chain must authenticate the default API"
                      + " chain through the shared SessionRepositoryFilter")
              .isEqualTo(200);
          assertThat(next.getRequest())
              .as("authenticated request must reach the downstream filter")
              .isNotNull();
        });
  }

  private static String encodedCookieValue(final String sessionId) {
    return Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
  }

  private static SessionRepositoryFilter<?> sessionRepositoryFilter(
      final SecurityFilterChain chain) {
    return chain.getFilters().stream()
        .filter(SessionRepositoryFilter.class::isInstance)
        .map(f -> (SessionRepositoryFilter<?>) f)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
  }

  private static MapSessionRepository sessionRepository(final SessionRepositoryFilter<?> filter) {
    return WebSessionTestAccess.mapRepositoryOf(filter);
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return StubSecurityPaths.builder().build();
    }
  }

  @Configuration
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      // Never invoked by these tests: they authenticate via a pre-seeded session, not credentials.
      return username -> null;
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
