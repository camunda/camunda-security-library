/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;

/**
 * Shared repository-resolution fallback: the durable {@link WebSessionRepository} bean when
 * present, otherwise a fresh in-memory {@link MapSessionRepository}. Used by both the default
 * (non-scoped) surface and physical-tenant scopes so the two can't drift apart.
 */
public final class WebSessionRepositories {

  private WebSessionRepositories() {}

  public static SessionRepository<?> durableOrInMemory(final WebSessionRepository durable) {
    return durable != null ? durable : new MapSessionRepository(new ConcurrentHashMap<>());
  }
}
