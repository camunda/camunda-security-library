/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

/**
 * Outbound port that yields the {@link SessionStorePort} bound to a single security scope.
 *
 * <p>When a host contributes path-scoped security chains (see {@code
 * CamundaSecurityScopeProvider}), each scope's persistent web sessions must be stored in that
 * scope's own storage. Rather than route a shared {@link SessionStorePort} at call time from
 * request/thread context — which is unavailable during Spring Session's commit phase (it runs after
 * the request scope is torn down) — the library binds each scope's {@code SessionRepositoryFilter}
 * to its own {@code WebSessionRepository} backed by the port returned here. Routing is then
 * structural: the store is decided by which scoped filter handles the request, not by ambient
 * context. See ADR-0009.
 *
 * <p>Keyed by {@code basePath} — the scope identity the library owns — so the library stays
 * scope-agnostic; the host maps {@code basePath} to its own notion of a scope (for example a
 * physical tenant) internally. Each returned port is bound to exactly one store.
 *
 * <p>This SPI is optional. When no such bean is present, the library falls back to its existing
 * behaviour (a shared {@code SessionStorePort}-backed repository, or a per-scope in-memory
 * repository for dev/test).
 */
public interface ScopedSessionStorePortProvider {

  /**
   * Returns the session store bound to the scope identified by {@code basePath}.
   *
   * @param basePath the scope's base path (for example {@code /physical-tenants/tenant-a})
   * @return the {@link SessionStorePort} for that scope's storage; never {@code null}
   */
  SessionStorePort forBasePath(String basePath);
}
