/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import java.lang.ref.WeakReference;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Carries the chain a {@link SecurityFilterChain#matches} call selected to the {@link
 * SecurityFilterChain#getFilters()} call that follows it.
 *
 * <p>{@code FilterChainProxy} asks a chain whether it matches and then, on the same thread and with
 * nothing in between, for its filters; {@code getFilters()} takes no request. A chain whose
 * delegate can change between the two calls pins the delegate it matched with, so the request runs
 * the filters of the very generation that matched it.
 *
 * <p>The pin is weak and consumed on read. A {@code matches} call that no {@code getFilters} call
 * follows (a privilege evaluator, for example) leaves at most one stale weak reference per thread,
 * which keeps no retired generation reachable.
 */
final class GenerationPin {

  private final ThreadLocal<WeakReference<SecurityFilterChain>> pinned = new ThreadLocal<>();

  void pin(final SecurityFilterChain chain) {
    pinned.set(new WeakReference<>(chain));
  }

  void clear() {
    pinned.remove();
  }

  /** The pinned chain, or {@code null}; the pin is cleared either way. */
  SecurityFilterChain take() {
    final var reference = pinned.get();
    if (reference == null) {
      return null;
    }
    pinned.remove();
    return reference.get();
  }
}
