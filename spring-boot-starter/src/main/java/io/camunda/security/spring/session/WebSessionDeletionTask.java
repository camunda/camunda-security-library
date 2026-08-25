/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import java.util.Collection;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Periodic task that evicts expired web sessions from <em>every</em> session store. Each store is a
 * single-store {@link WebSessionRepository}; the sweep iterates them all rather than relying on a
 * cross-store fan-out, keeping every store isolated to one repository (ADR-0012). The set of
 * repositories is resolved per run so per-scope stores created after startup are picked up.
 */
public final class WebSessionDeletionTask implements Runnable {

  public static final int DELETE_EXPIRED_SESSIONS_INITIAL_DELAY = 1_000 * 60 * 5;
  public static final int DELETE_EXPIRED_SESSIONS_RUN_DELAY = 1_000 * 60 * 10;
  private static final Logger LOGGER = LoggerFactory.getLogger(WebSessionDeletionTask.class);
  private final Supplier<Collection<WebSessionRepository>> repositoriesSupplier;

  public WebSessionDeletionTask(
      final Supplier<Collection<WebSessionRepository>> repositoriesSupplier) {
    this.repositoriesSupplier = repositoriesSupplier;
  }

  @Override
  public void run() {
    for (final WebSessionRepository repository : repositoriesSupplier.get()) {
      try {
        repository.deleteExpiredWebSessions();
      } catch (final Exception e) {
        // isolate failures so one unreachable store does not block sweeping the others
        LOGGER.warn(
            "Failed to delete expired web sessions from a session store: {}", e.getMessage(), e);
      }
    }
  }
}
