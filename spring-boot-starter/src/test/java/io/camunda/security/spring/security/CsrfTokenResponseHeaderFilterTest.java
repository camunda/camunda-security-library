/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

/**
 * Direct coverage for {@code SecurityFilterChainSupport#csrfTokenResponseHeaderFilter()}. The
 * filter must write {@code X-CSRF-TOKEN} so that the value survives even when downstream filters
 * commit the response — large bodies or gzip-compressed responses flush the response buffer during
 * chain dispatch, and {@link HttpServletResponse#setHeader} is a no-op once the response is
 * committed. This is the regression boundary for camunda/camunda-security-library#202.
 */
class CsrfTokenResponseHeaderFilterTest {

  private static final CsrfToken TOKEN =
      new DefaultCsrfToken(X_CSRF_TOKEN, "_csrf", "test-token-value");

  @AfterEach
  void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void writesHeaderBeforeChainDispatchForAuthenticatedGet() throws Exception {
    // The header must be observable on the response by the time the chain runs — otherwise a
    // downstream filter that commits the response (gzip, large body) renders setHeader a no-op
    // and the SPA never sees the token in the response header it caches.
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "user", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));

    final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
    request.setAttribute(CsrfToken.class.getName(), TOKEN);
    final var response = new MockHttpServletResponse();

    final var observedAtChainDispatch = new AtomicReference<String>();
    final FilterChain chain =
        (req, res) ->
            observedAtChainDispatch.set(((HttpServletResponse) res).getHeader(X_CSRF_TOKEN));

    SecurityFilterChainSupport.csrfTokenResponseHeaderFilter().doFilter(request, response, chain);

    assertThat(observedAtChainDispatch.get())
        .as(
            "X-CSRF-TOKEN must be set on the response BEFORE chain dispatch so that downstream"
                + " response commits (gzip flush, buffer overflow) cannot strip it")
        .isEqualTo(TOKEN.getToken());
  }

  @Test
  void doesNotWriteHeaderForLogoutRequest() throws Exception {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "user", null, List.of(new SimpleGrantedAuthority("ROLE_USER"))));

    final var request = new MockHttpServletRequest("GET", "/logout");
    request.setAttribute(CsrfToken.class.getName(), TOKEN);
    final var response = new MockHttpServletResponse();

    SecurityFilterChainSupport.csrfTokenResponseHeaderFilter()
        .doFilter(request, response, (req, res) -> {});

    assertThat(response.getHeader(X_CSRF_TOKEN)).isNull();
  }

  @Test
  void doesNotWriteHeaderForUnauthenticatedNonLoginRequest() throws Exception {
    SecurityContextHolder.clearContext();

    final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
    request.setAttribute(CsrfToken.class.getName(), TOKEN);
    final var response = new MockHttpServletResponse();

    SecurityFilterChainSupport.csrfTokenResponseHeaderFilter()
        .doFilter(request, response, (req, res) -> {});

    assertThat(response.getHeader(X_CSRF_TOKEN)).isNull();
  }
}
