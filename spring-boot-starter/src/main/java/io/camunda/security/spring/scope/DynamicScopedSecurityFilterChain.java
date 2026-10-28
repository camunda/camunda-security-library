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
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.core.Ordered;
import org.springframework.security.web.SecurityFilterChain;

/**
 * A single registered {@link SecurityFilterChain} that fronts every scope added after startup.
 *
 * <p>{@link org.springframework.security.web.FilterChainProxy} fixes its chain list once the
 * context is up, so a scope that appears later cannot get a chain bean of its own. Instead this
 * chain stays registered for the lifetime of the context and holds the scope chains in an immutable
 * snapshot that {@link #replace} publishes atomically. {@link #matches} is true when any scope
 * chain matches; its single filter then runs the matching scope chain's filters.
 *
 * <p>A scope that disappears is dropped from the snapshot, so nothing keeps its chain reachable and
 * its requests fall through to the host's catch-all chain like any unknown path.
 */
final class DynamicScopedSecurityFilterChain implements SecurityFilterChain, Ordered {

  private final int order;
  private final List<Filter> dispatcher = List.of(this::dispatch);
  private volatile Map<String, SecurityFilterChain> chainsByBasePath = Map.of();

  DynamicScopedSecurityFilterChain(final int order) {
    this.order = order;
  }

  /** Atomically replaces the scope chains. Requests already running keep the chains they hold. */
  void replace(final Map<String, ? extends SecurityFilterChain> chains) {
    chainsByBasePath = new LinkedHashMap<>(Objects.requireNonNull(chains, "chains"));
  }

  Map<String, SecurityFilterChain> chains() {
    return chainsByBasePath;
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    return find(request) != null;
  }

  @Override
  public List<Filter> getFilters() {
    return dispatcher;
  }

  @Override
  public int getOrder() {
    return order;
  }

  private SecurityFilterChain find(final HttpServletRequest request) {
    for (final var chain : chainsByBasePath.values()) {
      if (chain.matches(request)) {
        return chain;
      }
    }
    return null;
  }

  private void dispatch(
      final ServletRequest request, final ServletResponse response, final FilterChain next)
      throws IOException, ServletException {
    final var chain = find((HttpServletRequest) request);
    if (chain == null) {
      // The scope was removed between matches() and here: fail closed instead of skipping security.
      ((HttpServletResponse) response).sendError(HttpServletResponse.SC_NOT_FOUND);
      return;
    }
    new VirtualChain(chain.getFilters(), next).doFilter(request, response);
  }

  private static final class VirtualChain implements FilterChain {

    private final List<Filter> filters;
    private final FilterChain next;
    private int position;

    private VirtualChain(final List<Filter> filters, final FilterChain next) {
      this.filters = filters;
      this.next = next;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response)
        throws IOException, ServletException {
      if (position == filters.size()) {
        next.doFilter(request, response);
        return;
      }
      filters.get(position++).doFilter(request, response, this);
    }
  }
}
