/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * The place a scope's current generation is published, one per base path for the life of the
 * application context. Readers take {@link #current()} without locking; writers hold {@link
 * #lock()} so changes to one scope are serialized while other scopes change in parallel.
 *
 * <p>A slot outlives its scope: a removed scope keeps its slot holding a tombstone, so the base
 * path answers 404 and a scope added again at the same path reuses it.
 */
final class ScopeSlot {

  private final String basePath;
  private final boolean registeredAtStartup;
  private final String sessionCookieName;
  private final ReentrantLock lock = new ReentrantLock();
  private volatile ScopeGeneration current;
  private long lastNumber;
  private SessionRepositoryFilter<?> sessionFilter;

  ScopeSlot(final String basePath, final boolean registeredAtStartup) {
    this.basePath = basePath;
    this.registeredAtStartup = registeredAtStartup;
    sessionCookieName = ScopedSecurityChainRegistrar.sessionCookieName(basePath);
  }

  String basePath() {
    return basePath;
  }

  String sessionCookieName() {
    return sessionCookieName;
  }

  /**
   * Whether the scope has chain beans of its own (it was contributed at startup). Such a slot is
   * served by its {@link ScopeChainView}s; any other slot by the {@link
   * ScopeDispatchingSecurityFilterChain}.
   */
  boolean registeredAtStartup() {
    return registeredAtStartup;
  }

  ReentrantLock lock() {
    return lock;
  }

  /** The published generation, or {@code null} before the first one. */
  ScopeGeneration current() {
    return current;
  }

  /** The number the next generation of this slot takes. Call with {@link #lock()} held. */
  long nextNumber() {
    return ++lastNumber;
  }

  /**
   * The scope's session filter, shared by its API and webapp chains and kept across generations, so
   * a session outlives a credential rotation. Call with {@link #lock()} held.
   */
  SessionRepositoryFilter<?> sessionFilter(final Supplier<SessionRepositoryFilter<?>> create) {
    if (sessionFilter == null) {
      sessionFilter = create.get();
    }
    return sessionFilter;
  }

  /** Forgets the session filter of a removed scope. Call with {@link #lock()} held. */
  void dropSessionFilter() {
    sessionFilter = null;
  }

  /**
   * Publishes {@code next} and returns the generation it replaced. Call with {@link #lock()} held.
   */
  ScopeGeneration publish(final ScopeGeneration next) {
    final var previous = current;
    current = next;
    return previous;
  }
}
