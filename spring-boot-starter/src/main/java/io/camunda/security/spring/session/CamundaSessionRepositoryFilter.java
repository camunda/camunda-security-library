/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * A {@link SessionRepositoryFilter} that keeps a reference to the {@link SessionRepository} it was
 * built with, so the repository backing a given filter can be identified without reflecting on
 * Spring Session's private {@code sessionRepository} field.
 *
 * <p>Every {@link SessionRepositoryFilter} CSL installs on a chain is one of these: the default
 * (non-scoped) filter built by {@code DefaultWebSessionComponentsFactory} (ADR-0031) and the
 * per-scope filters built by {@code ScopedWebSessionComponentsFactory} (ADR-0027).
 *
 * <p>Behaviour is entirely inherited. The superclass keeps its own reference to the repository and
 * performs all session resolution and commit work; this subclass only remembers what it was handed.
 * The accessor is package-private: it exists so tests can assert which store a chain's filter is
 * bound to, not as a host-facing API.
 */
public final class CamundaSessionRepositoryFilter<S extends Session>
    extends SessionRepositoryFilter<S> {

  private final SessionRepository<S> sessionRepository;

  public CamundaSessionRepositoryFilter(final SessionRepository<S> sessionRepository) {
    super(sessionRepository);
    this.sessionRepository = sessionRepository;
  }

  /** The repository this filter resolves and commits sessions through. */
  SessionRepository<S> sessionRepository() {
    return sessionRepository;
  }
}
