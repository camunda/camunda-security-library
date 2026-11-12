/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.util.StringUtils;

/**
 * The place the primary (unscoped) chains publish their generations (ADR-0040), as a {@link
 * ScopeSlot} does for a scope. The chain beans the application builds at startup are registered
 * here and replaced by views that serve them until the first change, and the published generation
 * after it, so {@code FilterChainProxy} keeps the same chain beans for the life of the context.
 *
 * <p>Every chain serving the primary paths marks its generation, the startup chains included, so
 * the primary session repository binds a session to the configuration it was created under.
 */
public final class PrimaryChains {

  /** The base path a result of a primary change reports. */
  static final String BASE_PATH = "/";

  /** The key the generation marker and the session repository know the primary chains by. */
  static final String MARKER_KEY = "";

  private final AuthenticationConfiguration startupAuthentication;
  private final ScopeFingerprints startupFingerprints;
  private final Set<String> startupIssuers;
  private final Map<ScopeChainKind, SecurityFilterChain> startupChains =
      new EnumMap<>(ScopeChainKind.class);
  private final ReentrantLock lock = new ReentrantLock();
  private volatile ScopeGeneration current;
  private volatile SessionRepositoryFilter<?> sessionFilter;
  private long lastNumber = 1;

  public PrimaryChains(final AuthenticationConfiguration startupAuthentication) {
    this.startupAuthentication =
        startupAuthentication != null ? startupAuthentication : new AuthenticationConfiguration();
    startupFingerprints = ScopeFingerprints.of(this.startupAuthentication);
    startupIssuers = issuers(this.startupAuthentication);
  }

  /**
   * Registers the API chain built at startup.
   *
   * @return the chain to register with {@code FilterChainProxy} instead
   */
  public SecurityFilterChain api(
      final SecurityFilterChain startupChain,
      final SessionRepositoryFilter<?> sessionFilter,
      final int order) {
    return register(ScopeChainKind.API, startupChain, sessionFilter, order);
  }

  /**
   * Registers the webapp chain built at startup.
   *
   * @return the chain to register with {@code FilterChainProxy} instead
   */
  public SecurityFilterChain webapp(
      final SecurityFilterChain startupChain,
      final SessionRepositoryFilter<?> sessionFilter,
      final int order) {
    return register(ScopeChainKind.WEBAPP, startupChain, sessionFilter, order);
  }

  /**
   * The authentication fingerprint of the primary generation serving this thread, or {@code null}
   * when no primary chain serves it.
   */
  public static String servingFingerprint() {
    return ScopeGenerationMarkerFilter.servingFingerprint(MARKER_KEY);
  }

  private synchronized SecurityFilterChain register(
      final ScopeChainKind kind,
      final SecurityFilterChain startupChain,
      final SessionRepositoryFilter<?> sessionFilter,
      final int order) {
    if (startupChains.containsKey(kind)) {
      throw new IllegalStateException("A primary " + kind + " chain is already registered");
    }
    startupChains.put(
        kind,
        new MarkedChain(
            startupChain,
            new ScopeGenerationMarkerFilter(MARKER_KEY, 1, startupFingerprints.authentication())));
    this.sessionFilter = sessionFilter;
    return new PrimaryChainView(this, kind, order);
  }

  boolean serves(final ScopeChainKind kind) {
    return startupChains.containsKey(kind);
  }

  /** The chain of {@code kind} serving requests now. */
  SecurityFilterChain chain(final ScopeChainKind kind) {
    final var generation = current;
    return generation != null ? generation.chain(kind) : startupChains.get(kind);
  }

  ReentrantLock lock() {
    return lock;
  }

  /** The published generation, or {@code null} while the startup chains serve. */
  ScopeGeneration current() {
    return current;
  }

  long currentNumber() {
    final var generation = current;
    return generation != null ? generation.number() : 1;
  }

  AuthenticationConfiguration authentication() {
    final var generation = current;
    return generation != null ? generation.authentication() : startupAuthentication;
  }

  ScopeFingerprints fingerprints() {
    final var generation = current;
    return generation != null ? generation.fingerprints() : startupFingerprints;
  }

  /** The issuers the serving chains are configured with. */
  Set<String> issuersInUse() {
    final var generation = current;
    return generation != null ? generation.issuers() : startupIssuers;
  }

  SessionRepositoryFilter<?> sessionFilter() {
    return sessionFilter;
  }

  /** The number the next generation takes. Call with {@link #lock()} held. */
  long nextNumber() {
    return ++lastNumber;
  }

  /**
   * Publishes {@code next} and returns the generation it replaced. Call with {@link #lock()} held.
   */
  ScopeGeneration publish(final ScopeGeneration next) {
    final var previous = current;
    current = next;
    return previous;
  }

  private static Set<String> issuers(final AuthenticationConfiguration authentication) {
    final Set<String> issuers = new HashSet<>();
    final var oidc = authentication.getOidc();
    if (oidc != null && StringUtils.hasText(oidc.getIssuerUri())) {
      issuers.add(oidc.getIssuerUri());
    }
    if (authentication.getProviders() != null && authentication.getProviders().getOidc() != null) {
      authentication.getProviders().getOidc().values().stream()
          .map(OidcConfiguration::getIssuerUri)
          .filter(StringUtils::hasText)
          .forEach(issuers::add);
    }
    return Set.copyOf(issuers);
  }

  /** A startup chain whose first filter marks the startup generation. */
  private static final class MarkedChain implements SecurityFilterChain {

    private final SecurityFilterChain delegate;
    private final List<Filter> filters;

    private MarkedChain(final SecurityFilterChain delegate, final Filter marker) {
      this.delegate = delegate;
      final List<Filter> marked = new ArrayList<>();
      marked.add(marker);
      marked.addAll(delegate.getFilters());
      filters = List.copyOf(marked);
    }

    @Override
    public boolean matches(final HttpServletRequest request) {
      return delegate.matches(request);
    }

    @Override
    public List<Filter> getFilters() {
      return filters;
    }

    @Override
    public String toString() {
      return delegate.toString();
    }
  }
}
