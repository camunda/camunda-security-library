/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context.holder;

import static java.time.temporal.ChronoUnit.MILLIS;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.camunda.security.api.context.CamundaAuthenticationHolder;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Associates a {@link CamundaAuthentication} to an existing {@link HttpSession}. As long as the
 * {@link HttpSession} stays active, the same {@link CamundaAuthentication} is returned.
 *
 * <p>Refresh dedup does not rely on {@link HttpSession} object identity: under Spring Session,
 * {@code SessionRepository.findById(id)} returns a distinct object per call for the same underlying
 * session, so a lock on the {@link HttpSession} instance would not serialize concurrent requests
 * against the same session id. Instead, {@link #refreshClaims} is a JVM-local, session-id-keyed
 * guard that is the authority for "has this session already been refreshed", independent of any
 * single request's {@link HttpSession} snapshot (see ADR-0035).
 */
public class HttpSessionBasedAuthenticationHolder implements CamundaAuthenticationHolder {

  public static final String CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY =
      "io.camunda.security.session:CamundaAuthentication";
  public static final String LAST_REFRESH_ATTR = "AUTH_LAST_REFRESH";

  private static final Duration REFRESH_CLAIM_TTL = Duration.ofMinutes(30);
  private static final long REFRESH_CLAIM_MAX_SIZE = 10_000;

  private final Duration authenticationRefreshInterval;
  private final HttpServletRequest request;
  private final Cache<String, Instant> refreshClaims;

  public HttpSessionBasedAuthenticationHolder(
      final HttpServletRequest request,
      final AuthenticationConfiguration authenticationConfiguration) {
    this.request = request;
    authenticationRefreshInterval =
        Duration.parse(authenticationConfiguration.getAuthenticationRefreshInterval());
    refreshClaims =
        Caffeine.newBuilder()
            .expireAfterWrite(REFRESH_CLAIM_TTL)
            .maximumSize(REFRESH_CLAIM_MAX_SIZE)
            .build();
  }

  @Override
  public boolean supports() {
    return request.getSession(false) != null;
  }

  @Override
  public void set(final CamundaAuthentication authentication) {
    Optional.ofNullable(getHttpSession())
        .ifPresent(session -> setCamundaAuthenticationInSession(session, authentication));
  }

  @Override
  public CamundaAuthentication get() {
    return Optional.ofNullable(getHttpSession())
        .map(this::getCamundaAuthenticationFromSessionIfExists)
        .orElse(null);
  }

  @Override
  public void clear() {
    Optional.ofNullable(getHttpSession()).ifPresent(this::removeCamundaAuthenticationInSession);
  }

  protected HttpSession getHttpSession() {
    return request.getSession(false);
  }

  protected CamundaAuthentication getCamundaAuthenticationFromSessionIfExists(
      final HttpSession session) {
    final Instant now = Instant.now();
    final Instant lastRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);
    if (lastRefresh != null && isRefreshRequired(lastRefresh, now)) {
      lockAndRefresh(session, now);
    }
    return (CamundaAuthentication) session.getAttribute(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY);
  }

  private void lockAndRefresh(final HttpSession session, final Instant now) {
    // captured once: session.getId() can itself throw if the session is invalidated
    // concurrently, and the rollback path below must not risk a second, possibly-throwing call
    // masking the original refresh failure.
    final String sessionId = session.getId();
    final AtomicBoolean shouldRefresh = new AtomicBoolean(false);
    // compute() on the session id is the authority for the decision, not session.getAttribute():
    // concurrent requests against the same session id can each hold a distinct HttpSession
    // snapshot (see class javadoc / ADR-0035), so only a JVM-local guard keyed by the stable
    // session id — not the HttpSession object, and not its possibly-stale attribute state —
    // can dedup the refresh across them.
    refreshClaims
        .asMap()
        .compute(
            sessionId,
            (id, lastClaimed) -> {
              if (lastClaimed == null || isRefreshRequired(lastClaimed, now)) {
                shouldRefresh.set(true);
                return now;
              }
              return lastClaimed;
            });
    if (shouldRefresh.get()) {
      try {
        removeCamundaAuthenticationInSession(session);
        session.setAttribute(LAST_REFRESH_ATTR, now);
      } catch (final RuntimeException e) {
        // the claim was already advanced to `now` above; if the refresh itself failed (e.g. the
        // session was invalidated concurrently), roll it back so a later request is not blocked
        // from retrying for the remainder of the cache TTL. Guarded removal: only clears the
        // entry if it still holds the value this call just wrote.
        refreshClaims.asMap().remove(sessionId, now);
        throw e;
      }
    }
  }

  protected void setCamundaAuthenticationInSession(
      final HttpSession session, final CamundaAuthentication camundaAuthentication) {
    session.setAttribute(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY, camundaAuthentication);
    final Instant now = Instant.now();
    final Instant lastRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);
    if (lastRefresh == null) {
      initializeRefreshAttributes(session, now);
    }
  }

  public void removeCamundaAuthenticationInSession(final HttpSession session) {
    session.removeAttribute(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY);
  }

  private static void initializeRefreshAttributes(final HttpSession session, final Instant now) {
    session.setAttribute(LAST_REFRESH_ATTR, now);
  }

  private boolean isRefreshRequired(final Instant lastRefresh, final Instant now) {
    return MILLIS.between(lastRefresh, now) >= authenticationRefreshInterval.toMillis();
  }
}
