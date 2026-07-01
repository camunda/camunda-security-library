/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.Cookie;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.CookieSerializer.CookieValue;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Unit tests for the scope-aware session cookie serializer used by the global Spring Session
 * filter: with scopes present the session cookie stays per-scope and must not collapse to the
 * unscoped default {@code camunda-session} at {@code Path=/}.
 */
class ScopeAwareSessionCookieSerializerTest {

  private static final String BASE_A = "/apps/alpha";
  private static final String BASE_B = "/apps/beta";
  private static final String COOKIE_A = "camunda-session-apps-alpha";
  private static final String COOKIE_B = "camunda-session-apps-beta";
  private static final String DEFAULT_COOKIE = "camunda-session";

  private static CookieSerializer clusterDelegate() {
    final var delegate = new DefaultCookieSerializer();
    delegate.setCookieName(DEFAULT_COOKIE);
    return delegate;
  }

  private static ScopeAwareSessionCookieSerializer serializer() {
    return new ScopeAwareSessionCookieSerializer(List.of(BASE_A, BASE_B), clusterDelegate());
  }

  @Test
  void writesPerScopeCookieForScopedRequest() {
    // given
    final var serializer = serializer();
    final var request = new MockHttpServletRequest("GET", BASE_B + "/operate/dashboard");
    request.setContextPath("");
    final var response = new MockHttpServletResponse();

    // when
    serializer.writeCookieValue(new CookieValue(request, response, "sid-b"));

    // then — the per-scope cookie is written under scope B's Path, and the default is not set
    final var cookie = response.getCookie(COOKIE_B);
    assertThat(cookie).as("scoped request must receive the per-scope session cookie").isNotNull();
    assertThat(cookie.getPath()).isEqualTo(BASE_B);
    assertThat(response.getCookie(DEFAULT_COOKIE))
        .as("scoped request must NOT receive the unscoped default cookie")
        .isNull();
  }

  @Test
  void writesDefaultCookieForClusterRequest() {
    // given
    final var serializer = serializer();
    final var request = new MockHttpServletRequest("GET", "/operate/dashboard");
    request.setContextPath("");
    final var response = new MockHttpServletResponse();

    // when — a request that matches no scope
    serializer.writeCookieValue(new CookieValue(request, response, "sid-cluster"));

    // then — the deployment default cookie is used, no scoped cookies leak in
    assertThat(response.getCookie(DEFAULT_COOKIE)).isNotNull();
    assertThat(response.getCookie(COOKIE_A)).isNull();
    assertThat(response.getCookie(COOKIE_B)).isNull();
  }

  @Test
  void prependsContextPathToScopedCookiePath() {
    // given a deployment under a context path
    final var serializer = serializer();
    final var request = new MockHttpServletRequest("GET", "/ctx" + BASE_A + "/operate");
    request.setContextPath("/ctx");
    final var response = new MockHttpServletResponse();

    // when
    serializer.writeCookieValue(new CookieValue(request, response, "sid-a"));

    // then — Path is contextPath + basePath
    final var cookie = response.getCookie(COOKIE_A);
    assertThat(cookie).isNotNull();
    assertThat(cookie.getPath()).isEqualTo("/ctx" + BASE_A);
  }

  @Test
  void longestMatchingBasePathWins() {
    // given nested scopes
    final var serializer =
        new ScopeAwareSessionCookieSerializer(
            List.of(BASE_B, BASE_B + "/inner"), clusterDelegate());
    final var request = new MockHttpServletRequest("GET", BASE_B + "/inner/resource");
    request.setContextPath("");
    final var response = new MockHttpServletResponse();

    // when
    serializer.writeCookieValue(new CookieValue(request, response, "sid"));

    // then — the more specific scope's cookie is used
    assertThat(response.getCookie("camunda-session-apps-beta-inner")).isNotNull();
    assertThat(response.getCookie(COOKIE_B)).isNull();
  }

  @Test
  void readsScopedCookieByRequestPath() {
    // given — a scoped cookie round-tripped through the serializer (encoding-agnostic)
    final var serializer = serializer();
    final var writeResponse = new MockHttpServletResponse();
    final var writeRequest = new MockHttpServletRequest("GET", BASE_B + "/operate");
    writeRequest.setContextPath("");
    serializer.writeCookieValue(new CookieValue(writeRequest, writeResponse, "sid-b"));
    final var scopedValue = writeResponse.getCookie(COOKIE_B).getValue();

    // when — a scope B request carries scope B's cookie plus unrelated cookies
    final var readRequest = new MockHttpServletRequest("GET", BASE_B + "/operate");
    readRequest.setContextPath("");
    readRequest.setCookies(
        new Cookie(COOKIE_B, scopedValue),
        new Cookie(COOKIE_A, "sid-a"),
        new Cookie(DEFAULT_COOKIE, "sid-cluster"));

    // then — only scope B's session id is resolved
    assertThat(serializer.readCookieValues(readRequest)).containsExactly("sid-b");
  }

  @Test
  void readsDefaultCookieForClusterRequest() {
    // given
    final var serializer = serializer();
    final var writeResponse = new MockHttpServletResponse();
    final var writeRequest = new MockHttpServletRequest("GET", "/operate");
    writeRequest.setContextPath("");
    serializer.writeCookieValue(new CookieValue(writeRequest, writeResponse, "sid-cluster"));
    final var clusterValue = writeResponse.getCookie(DEFAULT_COOKIE).getValue();

    // when — a cluster request carries both the default and a scoped cookie
    final var readRequest = new MockHttpServletRequest("GET", "/operate");
    readRequest.setContextPath("");
    readRequest.setCookies(new Cookie(COOKIE_B, "sid-b"), new Cookie(DEFAULT_COOKIE, clusterValue));

    // then — only the default session id is resolved
    assertThat(serializer.readCookieValues(readRequest)).containsExactly("sid-cluster");
  }
}
