/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import java.util.function.Supplier;
import org.springframework.session.Session;

/**
 * Receives each web session that expired, right before {@link WebSessionRepository} deletes it. CSL
 * uses it to revoke the session's refresh token (ADR-0043). A failure in the handler never stops
 * the deletion.
 */
public interface ExpiredSessionHandler {

  /** A handler that does nothing. */
  ExpiredSessionHandler NONE =
      new ExpiredSessionHandler() {
        @Override
        public void foundByRequest(final Session session) {}

        @Override
        public void foundBySweep(final Session snapshot, final Supplier<Session> stillExpired) {}
      };

  /**
   * A request found {@code session} expired: when it loaded the session, or when it saved one that
   * expired while it ran. Must not wait, because the request waits on it.
   */
  void foundByRequest(Session session);

  /**
   * The expiry sweep found {@code snapshot} expired. The sweep runs on its own thread, so this may
   * wait. A request can use the session during that wait, so after waiting, act only on what {@code
   * stillExpired} returns: it reads the session from the store again and returns it while it is
   * still expired, or {@code null}. The repository deletes the session only if that read finds it
   * still expired, so a session that a request used in the meantime is kept.
   *
   * @param snapshot the session as the sweep's snapshot of the store holds it
   * @param stillExpired reads the session again; it reads the store once, however often it is
   *     called
   */
  void foundBySweep(Session snapshot, Supplier<Session> stillExpired);
}
