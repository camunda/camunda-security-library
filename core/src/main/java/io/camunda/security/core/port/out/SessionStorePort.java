/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.session.PersistentSession;
import java.util.List;

/**
 * Outbound port for storing and retrieving authenticated session state.
 *
 * <p>The library owns the session lifecycle (creation, expiry, deletion) and persists each session
 * through this port. Host applications provide the adapter backing it with their own storage
 * (database, search index, …). Implementations decide how to map the {@link PersistentSession}
 * boundary record to their storage model and are responsible for handling infrastructure failures
 * (for example retrying transient storage errors) without leaking them to the caller.
 */
public interface SessionStorePort {

  /**
   * Returns the persisted session with the given id, or {@code null} if no such session exists.
   *
   * @param sessionId the session id to look up
   * @return the persisted session, or {@code null} when absent
   */
  PersistentSession get(String sessionId);

  /** Inserts the session, or updates it in place when one with the same id already exists. */
  void upsert(PersistentSession session);

  /** Deletes the session with the given id; a no-op when no such session exists. */
  void delete(String sessionId);

  /** Returns all persisted sessions, used to scan for and evict expired ones. */
  List<PersistentSession> getAll();
}
