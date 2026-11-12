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
import org.springframework.core.Ordered;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The API or webapp chain of the primary paths as registered with {@code FilterChainProxy}: it
 * presents the generation serving now, and pins the one that matched a request for the {@link
 * #getFilters()} call that follows, as {@link ScopeChainView} does for a startup scope.
 */
final class PrimaryChainView implements SecurityFilterChain, Ordered {

  private final PrimaryChains primary;
  private final ScopeChainKind kind;
  private final int order;
  private final GenerationPin pin = new GenerationPin();

  PrimaryChainView(final PrimaryChains primary, final ScopeChainKind kind, final int order) {
    this.primary = primary;
    this.kind = kind;
    this.order = order;
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    final var chain = primary.chain(kind);
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
    return (matched != null ? matched : primary.chain(kind)).getFilters();
  }

  @Override
  public int getOrder() {
    return order;
  }

  @Override
  public String toString() {
    return "PrimaryChainView[" + kind + " generation " + primary.currentNumber() + "]";
  }
}
