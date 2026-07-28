/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.core.port.out.SessionStorePort;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Test-only access to the session store a {@link SessionRepositoryFilter} installed by CSL is bound
 * to, and to the {@link SessionStorePort} a {@link WebSessionRepository} writes through.
 *
 * <p>Lives in the production package on purpose: both accessors it delegates to ({@link
 * CamundaSessionRepositoryFilter#sessionRepository()} and {@link
 * WebSessionRepository#sessionStorePort()}) are package-private, so tests in other packages can
 * reach them here without reflecting on private fields. Reflecting on Spring Session's own {@code
 * SessionRepositoryFilter.sessionRepository} field was the previous approach and coupled CSL tests
 * to a framework implementation detail (see ADR-0039).
 */
public final class WebSessionTestAccess {

  private WebSessionTestAccess() {}

  /**
   * The repository backing the given filter.
   *
   * @throws AssertionError if the filter was not built by one of CSL's session component factories,
   *     which means production code bypassed {@link CamundaSessionRepositoryFilter}
   */
  public static SessionRepository<?> repositoryOf(final SessionRepositoryFilter<?> filter) {
    if (!(filter instanceof final CamundaSessionRepositoryFilter<?> camundaFilter)) {
      throw new AssertionError(
          "Expected a CamundaSessionRepositoryFilter so the backing repository is observable, got: "
              + filter.getClass());
    }
    return camundaFilter.sessionRepository();
  }

  /**
   * The in-memory repository backing the given filter.
   *
   * @throws AssertionError if the filter is not backed by a {@link MapSessionRepository}
   */
  public static MapSessionRepository mapRepositoryOf(final SessionRepositoryFilter<?> filter) {
    final var repository = repositoryOf(filter);
    if (!(repository instanceof final MapSessionRepository mapRepository)) {
      throw new AssertionError(
          "Expected MapSessionRepository backing the filter, got: " + repository.getClass());
    }
    return mapRepository;
  }

  /**
   * The durable repository backing the given filter.
   *
   * @throws AssertionError if the filter is not backed by a {@link WebSessionRepository}
   */
  public static WebSessionRepository durableRepositoryOf(final SessionRepositoryFilter<?> filter) {
    final var repository = repositoryOf(filter);
    if (!(repository instanceof final WebSessionRepository webSessionRepository)) {
      throw new AssertionError(
          "Expected a durable WebSessionRepository backing the filter, got: "
              + repository.getClass());
    }
    return webSessionRepository;
  }

  /** The store the given durable repository reads and writes sessions through. */
  public static SessionStorePort storePortOf(final WebSessionRepository repository) {
    return repository.sessionStorePort();
  }
}
