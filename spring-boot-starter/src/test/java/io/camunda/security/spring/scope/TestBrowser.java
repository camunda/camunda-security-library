/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.spring.scope.ScopeRuntimeTestSupport.Sent;
import jakarta.servlet.http.Cookie;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.FilterChainProxy;

/**
 * Sends requests through a {@link FilterChainProxy} with the cookies earlier responses set, so a
 * test can walk an OIDC login and use the session it ends in.
 */
final class TestBrowser {

  private final FilterChainProxy proxy;
  private final Map<String, String> cookies = new LinkedHashMap<>();

  TestBrowser(final FilterChainProxy proxy) {
    this.proxy = proxy;
  }

  /** GET of a path that may carry a query string. */
  Sent get(final String pathAndQuery) throws Exception {
    final var queryStart = pathAndQuery.indexOf('?');
    final var path = queryStart < 0 ? pathAndQuery : pathAndQuery.substring(0, queryStart);
    final var request = new MockHttpServletRequest("GET", path);
    if (queryStart >= 0) {
      final var query = pathAndQuery.substring(queryStart + 1);
      request.setQueryString(query);
      for (final var pair : query.split("&")) {
        final var separator = pair.indexOf('=');
        request.addParameter(
            URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8),
            URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8));
      }
    }
    if (!cookies.isEmpty()) {
      request.setCookies(
          cookies.entrySet().stream()
              .map(cookie -> new Cookie(cookie.getKey(), cookie.getValue()))
              .toArray(Cookie[]::new));
    }
    final var sent = ScopeRuntimeTestSupport.send(proxy, request);
    for (final var cookie : sent.response().getCookies()) {
      if (cookie.getMaxAge() == 0 || cookie.getValue() == null || cookie.getValue().isEmpty()) {
        cookies.remove(cookie.getName());
      } else {
        cookies.put(cookie.getName(), cookie.getValue());
      }
    }
    return sent;
  }

  String cookie(final String name) {
    return cookies.get(name);
  }

  void forget(final String name) {
    cookies.remove(name);
  }
}
