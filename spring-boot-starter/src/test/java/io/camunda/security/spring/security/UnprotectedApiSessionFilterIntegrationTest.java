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
import io.camunda.security.spring.testsupport.StubSecurityPaths;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Regression test for the {@code unprotected-api=true} surface: a web session minted on the webapp
 * chain must be resolvable on the unprotected API chain, so an unprotected endpoint such as {@code
 * /v2/authentication/me} still recognises the logged-in user.
 *
 * <p>ADR-0031 replaced the container-wide {@code @EnableSpringHttpSession} filter with an explicit
 * per-chain {@link SessionRepositoryFilter}. The unprotected API chain must therefore install the
 * shared default session filter just like the protected webapp/API chains; without it the {@code
 * camunda-session} cookie is never resolved and the request is seen as anonymous.
 */
class UnprotectedApiSessionFilterIntegrationTest {

  private static final String WEBAPP_CHAIN_BEAN = "basicAuthWebappSecurityFilterChain";
  private static final String UNPROTECTED_CHAIN_BEAN = "unprotectedApiSecurityFilterChain";
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
                  UnprotectedApiSecurityConfiguration.class,
                  AuthFailureHandlerConfiguration.class,
                  UserConfiguration.class))
          .withPropertyValues(
              "camunda.security.authentication.method=basic",
              "camunda.security.authentication.unprotected-api=true");

  @Test
  void unprotectedApiChainSharesTheDefaultSessionRepositoryFilter() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();
          assertThat(ctx).hasSingleBean(SessionRepositoryFilter.class);

          final var webappChain = ctx.getBean(WEBAPP_CHAIN_BEAN, SecurityFilterChain.class);
          final var unprotectedChain =
              ctx.getBean(UNPROTECTED_CHAIN_BEAN, SecurityFilterChain.class);

          assertThat(sessionRepositoryFilter(unprotectedChain))
              .as(
                  "the unprotected API chain must install the same shared SessionRepositoryFilter"
                      + " as the webapp chain, so a webapp-minted session is resolvable on it")
              .isSameAs(sessionRepositoryFilter(webappChain));
        });
  }

  @Test
  void sessionMintedOnWebappChainIsRecognizedOnUnprotectedApiChain() throws Exception {
    runner.run(
        ctx -> {
          assertThat(ctx).hasNotFailed();

          final var webappChain = ctx.getBean(WEBAPP_CHAIN_BEAN, SecurityFilterChain.class);
          final var unprotectedChain =
              ctx.getBean(UNPROTECTED_CHAIN_BEAN, SecurityFilterChain.class);

          // given — an authenticated session seeded via the webapp chain's session store
          final var repo = sessionRepository(sessionRepositoryFilter(webappChain));
          final var session = repo.createSession();
          final var principal =
              new UsernamePasswordAuthenticationToken(
                  "demo", null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
          session.setAttribute(
              HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
              new SecurityContextImpl(principal));
          repo.save(session);

          // when — the webapp-minted cookie is presented to the unprotected API chain
          final var captured = new AtomicReference<Authentication>();
          final Filter recorder =
              (req, res, chain) -> {
                captured.set(SecurityContextHolder.getContext().getAuthentication());
                chain.doFilter(req, res);
              };
          final var proxy = new FilterChainProxy(List.of(unprotectedChain));
          final var request = new MockHttpServletRequest("GET", "/api/authentication/me");
          request.setCookies(new Cookie(COOKIE_NAME, encodedCookieValue(session.getId())));
          final var response = new MockHttpServletResponse();
          proxy.doFilter(request, response, new MockFilterChain(new HttpServlet() {}, recorder));

          // then — the shared filter resolves the cookie and restores the SecurityContext
          assertThat(captured.get())
              .as(
                  "a session minted on the webapp chain must be recognised on the unprotected API"
                      + " chain, so endpoints like /v2/authentication/me see the logged-in user")
              .isNotNull();
          assertThat(captured.get().getName()).isEqualTo("demo");
        });
  }

  private static String encodedCookieValue(final String sessionId) {
    return Base64.getEncoder().encodeToString(sessionId.getBytes(StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private static SessionRepositoryFilter<MapSession> sessionRepositoryFilter(
      final SecurityFilterChain chain) {
    return chain.getFilters().stream()
        .filter(SessionRepositoryFilter.class::isInstance)
        .map(f -> (SessionRepositoryFilter<MapSession>) f)
        .findFirst()
        .orElseThrow(
            () -> new AssertionError("No SessionRepositoryFilter found on chain " + chain));
  }

  private static MapSessionRepository sessionRepository(
      final SessionRepositoryFilter<MapSession> filter) {
    try {
      final var field = SessionRepositoryFilter.class.getDeclaredField("sessionRepository");
      field.setAccessible(true);
      final Object repo = field.get(filter);
      if (!(repo instanceof MapSessionRepository mapRepo)) {
        throw new AssertionError(
            "Expected MapSessionRepository backing the filter, got: " + repo.getClass());
      }
      return mapRepo;
    } catch (final ReflectiveOperationException ex) {
      throw new AssertionError("Could not access sessionRepository field on filter", ex);
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
  static class StubUserDetailsPort {

    @Bean
    BasicAuthUserDetailsPort userDetailsPort() {
      // Never invoked: the test authenticates via a pre-seeded session, not credentials.
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
