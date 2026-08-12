/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.api.model.config.SessionConfiguration;
import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SessionStorePort;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Builds a per-scope {@link WebSessionRepository} backed by the scope's own {@link
 * io.camunda.security.core.port.out.SessionStorePort}, resolved through {@link
 * ScopedSessionStorePortProvider#forBasePath(String)}.
 *
 * <p>Used by {@code ScopedSecurityChainRegistrar} to give each scoped {@code
 * SessionRepositoryFilter} a repository bound to that scope's store, so persistent session
 * reads/writes route structurally at Spring Session's commit time instead of via request/thread
 * context. See ADR-0029.
 *
 * <p>The provider is optional: when a host contributes no {@link ScopedSessionStorePortProvider},
 * {@link #isAvailable()} returns {@code false} and callers fall back to the shared repository or a
 * per-scope in-memory one.
 *
 * <p>Repositories are built once per {@code basePath} and cached, so the expiry sweep can iterate
 * every per-scope store via {@link #builtRepositories()} (ADR-0029) — each store is swept by its
 * own single-store repository rather than through a cross-store fan-out.
 */
public final class ScopedWebSessionRepositoryFactory {

  private final ScopedSessionStorePortProvider storePortProvider;
  private final WebSessionMapper webSessionMapper;
  private final HttpServletRequest request;
  private final SessionConfiguration sessionConfiguration;
  private final Map<String, WebSessionRepository> repositoriesByBasePath =
      new ConcurrentHashMap<>();

  public ScopedWebSessionRepositoryFactory(
      final ScopedSessionStorePortProvider storePortProvider,
      final WebSessionMapper webSessionMapper,
      final HttpServletRequest request,
      final SessionConfiguration sessionConfiguration) {
    this.storePortProvider = storePortProvider;
    this.webSessionMapper = webSessionMapper;
    this.request = request;
    this.sessionConfiguration = sessionConfiguration;
  }

  /**
   * Whether a {@link ScopedSessionStorePortProvider} is present to build per-scope repositories.
   */
  public boolean isAvailable() {
    return storePortProvider != null;
  }

  /**
   * Returns (building on first use, then caching) the {@link WebSessionRepository} for the given
   * scope.
   *
   * @throws IllegalStateException if no {@link ScopedSessionStorePortProvider} is available
   */
  public WebSessionRepository forBasePath(final String basePath) {
    if (storePortProvider == null) {
      throw new IllegalStateException(
          "No ScopedSessionStorePortProvider available to build a per-scope WebSessionRepository for "
              + "basePath="
              + basePath);
    }
    return repositoriesByBasePath.computeIfAbsent(basePath, this::buildRepository);
  }

  /**
   * The per-scope repositories built so far — one single-store repository per scope. Consumed by
   * the expiry sweep to clean every store in turn (ADR-0029). By the time the first sweep runs, all
   * scoped chains have been instantiated, so every scope's repository is present.
   */
  public Collection<WebSessionRepository> builtRepositories() {
    return List.copyOf(repositoriesByBasePath.values());
  }

  private WebSessionRepository buildRepository(final String basePath) {
    final SessionStorePort storePort =
        Objects.requireNonNull(
            storePortProvider.forBasePath(basePath),
            () -> "ScopedSessionStorePortProvider returned null for basePath=" + basePath);
    return new WebSessionRepository(storePort, webSessionMapper, request, sessionConfiguration);
  }
}
