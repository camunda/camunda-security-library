/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class OidcRedirectDiagnosticsFilterTest {

  private static final String CALLBACK_PATH = "/sso-callback";

  @Mock private FilterChain chain;

  @Test
  void shouldComputeExternalBaseUrlFromForwardedHeaders() {
    // given - a request behind a reverse proxy terminating TLS on a non-default port
    final MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.setServerName("internal-host");
    request.addHeader("X-Forwarded-Proto", "https");
    request.addHeader("X-Forwarded-Host", "auth.example.com:8443");

    // when
    final String baseUrl = OidcRedirectDiagnosticsFilter.computeExternalBaseUrl(request);

    // then
    assertThat(baseUrl).isEqualTo("https://auth.example.com:8443");
  }

  @Test
  void shouldComputeExternalBaseUrlFromBracketedIpv6ForwardedHost() {
    // given - the reverse proxy reports a bracketed IPv6 host + port. A naive ':' split would
    // corrupt the IPv6 literal; the authority must be preserved verbatim.
    final MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.setServerName("internal-host");
    request.addHeader("X-Forwarded-Proto", "https");
    request.addHeader("X-Forwarded-Host", "[2001:db8::1]:8443");

    // when
    final String baseUrl = OidcRedirectDiagnosticsFilter.computeExternalBaseUrl(request);

    // then
    assertThat(baseUrl).isEqualTo("https://[2001:db8::1]:8443");
  }

  @Test
  void shouldHonourForwardedPrefixInExternalBaseUrl() {
    // given - the app is served under a path prefix by the proxy
    final MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.setServerName("internal-host");
    request.addHeader("X-Forwarded-Proto", "https");
    request.addHeader("X-Forwarded-Host", "auth.example.com");
    request.addHeader("X-Forwarded-Prefix", "/camunda/");

    // when
    final String baseUrl = OidcRedirectDiagnosticsFilter.computeExternalBaseUrl(request);

    // then - trailing slash on the prefix is stripped
    assertThat(baseUrl).isEqualTo("https://auth.example.com/camunda");
  }

  @Test
  void shouldExtractAndDecodeRedirectUriFromLocationHeader() {
    // given - a real authorization redirect Location, where
    // OAuth2AuthorizationRequestRedirectFilter percent-encodes the redirect_uri query value per the
    // OAuth2 spec
    final String location =
        "https://idp.example.com/authorize?client_id=x&redirect_uri=https%3A%2F%2Fapp.example.com%2Fsso-callback";

    // when
    final String redirectUri = OidcRedirectDiagnosticsFilter.extractRedirectUri(location);

    // then - returned decoded so it compares equal to the (plain) expected redirect URI; if it were
    // left encoded the mismatch WARN would fire on every login
    assertThat(redirectUri).isEqualTo("https://app.example.com/sso-callback");
  }

  @Test
  void shouldExtractAndDecodeRedirectUriWithEncodedPortAndPath() {
    // given - encoded redirect_uri including a port, as a proxied deployment would produce
    final String location =
        "https://idp.example.com/authorize?redirect_uri=https%3A%2F%2Fapp.example.com%3A8443%2Fcamunda%2Fsso-callback&client_id=x";

    // when
    final String redirectUri = OidcRedirectDiagnosticsFilter.extractRedirectUri(location);

    // then
    assertThat(redirectUri).isEqualTo("https://app.example.com:8443/camunda/sso-callback");
  }

  @Test
  void shouldReturnNullRedirectUriWhenLocationHasNoRedirectUriParam() {
    assertThat(
            OidcRedirectDiagnosticsFilter.extractRedirectUri("https://idp.example.com/authorize"))
        .isNull();
    assertThat(OidcRedirectDiagnosticsFilter.extractRedirectUri(null)).isNull();
    assertThat(OidcRedirectDiagnosticsFilter.extractRedirectUri("")).isNull();
  }

  @Test
  void shouldDetectAuthorizationRequests() {
    assertThat(OidcRedirectDiagnosticsFilter.isAuthorizationRequest("/oauth2/authorization/oidc"))
        .isTrue();
    assertThat(OidcRedirectDiagnosticsFilter.isAuthorizationRequest("/sso-callback")).isFalse();
    assertThat(OidcRedirectDiagnosticsFilter.isAuthorizationRequest(null)).isFalse();
  }

  @Test
  void shouldFlagCallbackWithCodeAndNoSessionAsLostSession() {
    // given - a callback carrying an authorization code but no HTTP session
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", CALLBACK_PATH);
    request.setParameter("code", "auth-code-123");

    // when / then
    assertThat(OidcRedirectDiagnosticsFilter.indicatesLostSession(request, CALLBACK_PATH)).isTrue();
  }

  @Test
  void shouldNotFlagCallbackWhenSessionIsPresent() {
    // given - a callback carrying a code and a valid session
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", CALLBACK_PATH);
    request.setParameter("code", "auth-code-123");
    request.getSession(true);

    // when / then
    assertThat(OidcRedirectDiagnosticsFilter.indicatesLostSession(request, CALLBACK_PATH))
        .isFalse();
  }

  @Test
  void shouldNotBreakChainWhenForwardedPortIsMalformed() throws Exception {
    // given - a reverse proxy that sends a non-numeric X-Forwarded-Port value; Spring's
    // UriComponentsBuilder rejects non-integer ports during URI assembly
    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.addHeader("X-Forwarded-Proto", "https");
    request.addHeader("X-Forwarded-Host", "auth.example.com");
    request.addHeader("X-Forwarded-Port", "not-a-port");
    final var response = new MockHttpServletResponse();
    final var filter = new OidcRedirectDiagnosticsFilter(CALLBACK_PATH);

    // when / then — the filter is purely observational; a bad header must never fail the request
    filter.doFilter(request, response, chain);
    verify(chain).doFilter(request, response);
  }

  @Test
  void shouldNotFlagNonCallbackRequestAsLostSession() {
    // given - an authorization request (not the callback) with no session
    final MockHttpServletRequest request =
        new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.setParameter("code", "auth-code-123");

    // when / then
    assertThat(OidcRedirectDiagnosticsFilter.indicatesLostSession(request, CALLBACK_PATH))
        .isFalse();
  }

  @Test
  void shouldWarnOnRedirectUriMismatch() throws Exception {
    // given - a request behind a proxy; the chain generates a Location whose redirect_uri has
    // a different port from the one computed from the forwarded headers
    final var request = new MockHttpServletRequest("GET", "/oauth2/authorization/oidc");
    request.addHeader("X-Forwarded-Proto", "https");
    request.addHeader("X-Forwarded-Host", "app.example.com");
    final var response = new MockHttpServletResponse();
    doAnswer(
            inv -> {
              ((HttpServletResponse) inv.getArgument(1))
                  .setHeader(
                      "Location",
                      "https://idp.example.com/authorize"
                          + "?redirect_uri=https%3A%2F%2Fapp.example.com%3A8443%2Fsso-callback");
              return null;
            })
        .when(chain)
        .doFilter(any(), any());
    final var filter = new OidcRedirectDiagnosticsFilter(CALLBACK_PATH);

    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      filter.doFilter(request, response, chain);
    } finally {
      detachAppender(appender);
    }

    // chain was always called — the filter is purely observational
    verify(chain).doFilter(request, response);
    // WARN about redirect_uri mismatch was logged
    assertThat(appender.list)
        .anySatisfy(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage()).contains("redirect_uri mismatch");
            });
    // filter did not mutate the response: only the Location header the chain set is present
    assertThat(response.getHeaderNames()).containsExactlyInAnyOrder("Location");
    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  void shouldWarnOnLostSession() throws Exception {
    // given - a callback carrying an authorization code but no HTTP session
    final var request = new MockHttpServletRequest("GET", CALLBACK_PATH);
    request.setParameter("code", "auth-code-abc");
    // no request.getSession(true) — session is intentionally absent
    final var response = new MockHttpServletResponse();
    final var filter = new OidcRedirectDiagnosticsFilter(CALLBACK_PATH);

    final ListAppender<ILoggingEvent> appender = attachAppender();
    try {
      filter.doFilter(request, response, chain);
    } finally {
      detachAppender(appender);
    }

    // chain was always called — the filter is purely observational
    verify(chain).doFilter(request, response);
    // WARN about missing session was logged
    assertThat(appender.list)
        .anySatisfy(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage()).contains("no valid HTTP session");
            });
    // filter did not mutate the response
    assertThat(response.getHeaderNames()).isEmpty();
    assertThat(response.getStatus()).isEqualTo(200);
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcRedirectDiagnosticsFilter.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(OidcRedirectDiagnosticsFilter.class);
    logger.detachAppender(appender);
  }
}
