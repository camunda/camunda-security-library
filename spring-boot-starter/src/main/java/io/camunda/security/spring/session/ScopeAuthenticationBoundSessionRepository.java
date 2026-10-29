/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import java.util.Objects;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

/**
 * Binds every session of a scope to the authentication configuration it was created under, so a
 * change to that configuration ends the sessions created before it (ADR-0040).
 *
 * <p>A new session records the authentication fingerprint of the configuration serving the request
 * that creates it. A session whose recorded fingerprint differs from the one serving the request
 * that reads it is deleted and reported as absent: the request then continues without a session,
 * and with it go the security context and the OAuth2 authorized clients — refresh tokens included —
 * stored in it. A rotated credential keeps the fingerprint, so it keeps the sessions.
 *
 * <p>The fingerprint serving the request is read from {@code servingFingerprint}. When it yields
 * {@code null} — no scope generation is serving the calling thread, as for the expiry sweep — the
 * repository passes through unchanged. A session that carries no fingerprint (created before this
 * repository existed) is adopted by the configuration that reads it first.
 *
 * <p>Sessions are checked when they are read, so a store a host owns keeps the ended sessions until
 * its own expiry removes them; none of them is accepted again.
 */
public final class ScopeAuthenticationBoundSessionRepository<S extends Session>
    implements SessionRepository<S> {

  /** The session attribute holding the fingerprint the session was created under. */
  public static final String FINGERPRINT_ATTRIBUTE =
      ScopeAuthenticationBoundSessionRepository.class.getName() + ".FINGERPRINT";

  private static final Logger LOG =
      LoggerFactory.getLogger(ScopeAuthenticationBoundSessionRepository.class);

  private final SessionRepository<S> delegate;
  private final String scopeDescription;
  private final Supplier<String> servingFingerprint;

  public ScopeAuthenticationBoundSessionRepository(
      final SessionRepository<S> delegate,
      final String scopeDescription,
      final Supplier<String> servingFingerprint) {
    this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    this.scopeDescription = scopeDescription;
    this.servingFingerprint =
        Objects.requireNonNull(servingFingerprint, "servingFingerprint must not be null");
  }

  @Override
  public S createSession() {
    final var session = delegate.createSession();
    final var fingerprint = servingFingerprint.get();
    if (fingerprint != null) {
      session.setAttribute(FINGERPRINT_ATTRIBUTE, fingerprint);
    }
    return session;
  }

  @Override
  public void save(final S session) {
    delegate.save(session);
  }

  @Override
  public S findById(final String id) {
    final var session = delegate.findById(id);
    final var fingerprint = servingFingerprint.get();
    if (session == null || fingerprint == null) {
      return session;
    }
    final String recorded = session.getAttribute(FINGERPRINT_ATTRIBUTE);
    if (recorded == null) {
      session.setAttribute(FINGERPRINT_ATTRIBUTE, fingerprint);
      return session;
    }
    if (recorded.equals(fingerprint)) {
      return session;
    }
    LOG.debug(
        "Ending a session of {}: it was created under an authentication configuration the scope"
            + " no longer serves",
        scopeDescription);
    delegate.deleteById(id);
    return null;
  }

  @Override
  public void deleteById(final String id) {
    delegate.deleteById(id);
  }

  /** The repository sessions are stored in. */
  SessionRepository<S> delegate() {
    return delegate;
  }
}
