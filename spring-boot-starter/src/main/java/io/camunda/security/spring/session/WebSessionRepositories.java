/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.api.model.config.SessionConfiguration;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;

/**
 * Shared repository-resolution fallback: the durable {@link WebSessionRepository} bean when
 * present, otherwise a fresh in-memory {@link MapSessionRepository}. Used by both the default
 * (non-scoped) surface and physical-tenant scopes so the two can't drift apart.
 */
public final class WebSessionRepositories {

  private static final Logger LOGGER = LoggerFactory.getLogger(WebSessionRepositories.class);

  private WebSessionRepositories() {}

  /**
   * @param sessionConfiguration source of both {@link
   *     SessionConfiguration#getMaxInactiveInterval()} — applied via {@link
   *     MapSessionRepository#setDefaultMaxInactiveInterval} when the in-memory fallback is used,
   *     ignored when {@code durable} is present since that repository already stamps the same
   *     configured value onto every session it creates (ADR-0023) — and {@link
   *     SessionConfiguration#getHeartbeat()}, consulted only to decide whether the WARN below
   *     applies.
   * @param surface a short, log-friendly label for the caller's surface (e.g. {@code "default"} or
   *     a scope's {@code basePath}), included in the WARN message so a misconfiguration is
   *     diagnosable in a multi-scope deployment without a debugger.
   */
  public static SessionRepository<?> durableOrInMemory(
      final WebSessionRepository durable,
      final SessionConfiguration sessionConfiguration,
      final String surface) {
    if (durable != null) {
      return durable;
    }
    if (sessionConfiguration.getHeartbeat().isEnabled()) {
      // MapSession (backing the in-memory fallback) has no equivalent of WebSession's
      // config-aware touch guard, so heartbeat.enabled has no effect here: every request keeps
      // extending the session's activity regardless of the flag. This is a silent behavioral gap
      // without this WARN — the host believes it configured activity-driven expiry and it simply
      // isn't happening (ADR-0023).
      LOGGER.warn(
          "camunda.security.session.heartbeat.enabled=true has no effect on the '{}' surface: it"
              + " is running the in-memory session fallback (no durable WebSessionRepository bean"
              + " present for this surface), which has no equivalent of the persistent path's"
              + " config-aware touch guard. Every request will continue to extend this surface's"
              + " session activity regardless of the flag. Enable"
              + " camunda.security.session.persistent.enabled (and supply a SessionStorePort) for"
              + " heartbeat-only activity to actually take effect here.",
          surface);
    }
    final var repository = new MapSessionRepository(new ConcurrentHashMap<>());
    repository.setDefaultMaxInactiveInterval(sessionConfiguration.getMaxInactiveInterval());
    return repository;
  }
}
