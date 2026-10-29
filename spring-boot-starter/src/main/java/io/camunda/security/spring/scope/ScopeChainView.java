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
import java.util.List;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The API or webapp chain of a scope contributed at startup, as registered with {@code
 * FilterChainProxy}. It always presents the slot's current generation, so the chain bean stays the
 * same while the scope is replaced or removed underneath it.
 *
 * <p>The generation that answered {@link #matches} is pinned for the {@link #getFilters()} call
 * that follows, so one request never runs the filters of a generation other than the one that
 * matched it. {@link #getFilters()} called on its own presents the current generation.
 */
final class ScopeChainView implements SecurityFilterChain {

  private final ScopeSlot slot;
  private final ScopeChainKind kind;
  private final GenerationPin pin = new GenerationPin();

  ScopeChainView(final ScopeSlot slot, final ScopeChainKind kind) {
    this.slot = slot;
    this.kind = kind;
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    final var chain = slot.current().chain(kind);
    if (chain.matches(request)) {
      pin.pin(chain);
      return true;
    }
    pin.clear();
    return false;
  }

  @Override
  public List<Filter> getFilters() {
    final var matched = pin.take();
    return (matched != null ? matched : slot.current().chain(kind)).getFilters();
  }

  ScopeSlot slot() {
    return slot;
  }

  ScopeChainKind kind() {
    return kind;
  }

  @Override
  public String toString() {
    return "ScopeChainView[" + kind + " " + slot.basePath() + "]";
  }
}
