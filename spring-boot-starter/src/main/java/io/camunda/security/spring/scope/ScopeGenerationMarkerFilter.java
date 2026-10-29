/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;

/**
 * The first filter of every chain of a scope generation. For the rest of the request it records
 * which generation serves it, so the scope's session repository binds a session to the
 * authentication configuration of that very generation — also when the scope was replaced while the
 * request ran.
 */
final class ScopeGenerationMarkerFilter implements Filter {

  /** The request attribute holding the {@link Serving} generation. */
  static final String SERVING_ATTRIBUTE = ScopeGenerationMarkerFilter.class.getName() + ".SERVING";

  private static final ThreadLocal<Serving> SERVING = new ThreadLocal<>();

  private final Serving serving;

  ScopeGenerationMarkerFilter(
      final String basePath, final long generation, final String authenticationFingerprint) {
    serving = new Serving(basePath, generation, authenticationFingerprint);
  }

  /**
   * The authentication fingerprint of the generation of {@code basePath} serving this thread, or
   * {@code null} when none does.
   */
  static String servingFingerprint(final String basePath) {
    final var current = SERVING.get();
    return current != null && current.basePath().equals(basePath)
        ? current.authenticationFingerprint()
        : null;
  }

  @Override
  public void doFilter(
      final ServletRequest request, final ServletResponse response, final FilterChain chain)
      throws IOException, ServletException {
    final var outer = SERVING.get();
    SERVING.set(serving);
    request.setAttribute(SERVING_ATTRIBUTE, serving);
    try {
      chain.doFilter(request, response);
    } finally {
      if (outer == null) {
        SERVING.remove();
      } else {
        SERVING.set(outer);
      }
    }
  }

  /** The generation of a scope serving a request. */
  record Serving(String basePath, long generation, String authenticationFingerprint) {}
}
