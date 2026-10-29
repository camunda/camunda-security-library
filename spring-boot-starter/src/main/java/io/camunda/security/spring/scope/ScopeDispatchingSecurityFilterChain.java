/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.core.Ordered;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The one registered chain that serves every scope added after startup.
 *
 * <p>{@code FilterChainProxy} fixes its chain list once the context is up, so a scope added later
 * cannot get chain beans of its own. This chain stays registered for the life of the context and
 * finds the scope of a request by its path: it looks each leading path prefix up in the {@link
 * ScopeSlots} index, so the cost of a request does not grow with the number of scopes.
 *
 * <p>Within the scope it takes one generation and asks its API chain first, then its webapp chain —
 * the order the two have as startup chains — and pins the chain that matched for the {@link
 * #getFilters()} call that follows. The request then runs that chain's own filters, so Spring
 * Security observes them one by one as it does for a startup scope.
 */
final class ScopeDispatchingSecurityFilterChain implements SecurityFilterChain, Ordered {

  /** Answers a {@link #getFilters()} call that no matching {@link #matches} call preceded. */
  private static final List<Filter> NOT_FOUND =
      List.of(
          (request, response, chain) ->
              ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND));

  private final ScopeSlots slots;
  private final int order;
  private final GenerationPin pin = new GenerationPin();

  ScopeDispatchingSecurityFilterChain(final ScopeSlots slots, final int order) {
    this.slots = slots;
    this.order = order;
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    final var slot = slots.runtimeSlotFor(request);
    final var generation = slot != null ? slot.current() : null;
    if (generation != null) {
      for (final var kind : ScopeChainKind.values()) {
        final var chain = generation.chain(kind);
        if (chain.matches(request)) {
          pin.pin(chain);
          return true;
        }
      }
    }
    pin.clear();
    return false;
  }

  @Override
  public List<Filter> getFilters() {
    final var matched = pin.take();
    return matched != null ? matched.getFilters() : NOT_FOUND;
  }

  @Override
  public int getOrder() {
    return order;
  }

  @Override
  public String toString() {
    return "ScopeDispatchingSecurityFilterChain[" + slots.runtimeScopeCount() + " scope(s)]";
  }
}
