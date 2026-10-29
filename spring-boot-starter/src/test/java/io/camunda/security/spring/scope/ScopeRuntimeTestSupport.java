/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import io.camunda.security.core.port.in.ScopedSecurityReloadPort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.lang.ref.WeakReference;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/** Drives requests through a context's chains and observes the scope runtime from tests. */
final class ScopeRuntimeTestSupport {

  private ScopeRuntimeTestSupport() {}

  static ScopedSecurityReloadPort reloadPort(final ApplicationContext ctx) {
    return ctx.getBean(ScopedSecurityReloadPort.class);
  }

  static ScopeSlots slots(final ApplicationContext ctx) {
    return ctx.getBean(ScopedSecurityReloadService.class).slots();
  }

  /** The generation the scope publishes, or {@code null}. */
  static ScopeGeneration generation(final ApplicationContext ctx, final String basePath) {
    final var slot = slots(ctx).find(basePath);
    return slot != null ? slot.current() : null;
  }

  /** The registered chains in the order {@code FilterChainProxy} consults them. */
  static List<SecurityFilterChain> chains(final ApplicationContext ctx) {
    final var chains = new ArrayList<>(ctx.getBeansOfType(SecurityFilterChain.class).values());
    chains.sort(AnnotationAwareOrderComparator.INSTANCE);
    return chains;
  }

  static FilterChainProxy proxy(final ApplicationContext ctx) {
    return new FilterChainProxy(chains(ctx));
  }

  /** Sends a request through the proxy the way the servlet container would. */
  static Sent send(final FilterChainProxy proxy, final MockHttpServletRequest request)
      throws Exception {
    final var response = new MockHttpServletResponse();
    final var next = new MockFilterChain();
    try {
      proxy.doFilter(request, response, next);
    } catch (final RuntimeException | ServletException escaped) {
      // what a servlet container answers for an exception that leaves the filter chain
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return new Sent(request, response, false);
    }
    return new Sent(request, response, next.getRequest() != null);
  }

  /** Status of a GET through every chain of the context. */
  static int status(final ApplicationContext ctx, final String path, final String authorization)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", path);
    if (authorization != null) {
      request.addHeader("Authorization", authorization);
    }
    return send(proxy(ctx), request).status();
  }

  static Cookie cookie(final MockHttpServletResponse response, final String name) {
    return response.getCookie(name);
  }

  static List<WeakReference<Object>> weakly(final List<?> objects) {
    return objects.stream().map(object -> new WeakReference<Object>(object)).toList();
  }

  /** Waits until the garbage collector has collected every referent. */
  static void assertCollected(final List<WeakReference<Object>> references) {
    await()
        .atMost(Duration.ofSeconds(30))
        .pollInterval(Duration.ofMillis(100))
        .untilAsserted(
            () -> {
              System.gc();
              assertThat(survivors(references)).as("still reachable after retirement").isEmpty();
            });
  }

  private static List<String> survivors(final List<WeakReference<Object>> references) {
    return references.stream()
        .map(WeakReference::get)
        .filter(Objects::nonNull)
        .map(object -> object.getClass().getName())
        .toList();
  }

  /** What a request through a proxy came back with. */
  record Sent(MockHttpServletRequest request, MockHttpServletResponse response, boolean served) {

    /** The status, 200 when every filter let the request through to the application. */
    int status() {
      return served ? 200 : response.getStatus();
    }

    /** The generation of the scope that served the request, or {@code null}. */
    ScopeGenerationMarkerFilter.Serving serving() {
      return (ScopeGenerationMarkerFilter.Serving)
          request.getAttribute(ScopeGenerationMarkerFilter.SERVING_ATTRIBUTE);
    }
  }
}
