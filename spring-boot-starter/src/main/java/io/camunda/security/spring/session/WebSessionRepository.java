/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.api.model.config.SessionConfiguration;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.security.CamundaSecurityFilterChainConstants;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.session.SessionRepository;

public final class WebSessionRepository implements SessionRepository<WebSession> {

  private static final Logger LOGGER = LoggerFactory.getLogger(WebSessionRepository.class);
  private static final String POLLING_HEADER = "x-is-polling";

  private final SessionStorePort sessionStorePort;
  private final WebSessionMapper webSessionMapper;
  private final HttpServletRequest request;
  private final SessionConfiguration sessionConfiguration;

  public WebSessionRepository(
      final SessionStorePort sessionStorePort,
      final WebSessionMapper webSessionMapper,
      final HttpServletRequest request,
      final SessionConfiguration sessionConfiguration) {
    this.sessionStorePort = sessionStorePort;
    this.webSessionMapper = webSessionMapper;
    this.request = request;
    this.sessionConfiguration = sessionConfiguration;
  }

  /**
   * The {@link SessionStorePort} this repository writes to. Used by the expiry sweep to deduplicate
   * repositories that share a backing store, so each store is swept once (ADR-0012).
   */
  SessionStorePort sessionStorePort() {
    return sessionStorePort;
  }

  @Override
  public WebSession createSession() {
    final var sessionId = UUID.randomUUID().toString().replace("-", "");
    final var session = new WebSession(sessionId);
    session.setMaxInactiveInterval(sessionConfiguration.getMaxInactiveInterval());
    LOGGER.debug(
        "Create session {} with maxInactiveInterval {} s",
        session,
        session.getMaxInactiveInterval());
    return session;
  }

  @Override
  public void save(final WebSession webSession) {
    LOGGER.debug("Save session {}", webSession.getId());
    if (!webSession.shouldBeDeleted()) {
      saveWebSessionIfChanged(webSession);
    } else {
      deleteById(webSession.getId());
    }
  }

  @Override
  public WebSession findById(final String id) {
    LOGGER.debug("Retrieve session {}", id);
    return Optional.ofNullable(id)
        .filter(this::isSessionIdNotEmpty)
        .map(sessionStorePort::get)
        .map(this::getWebSessionIfNotExpired)
        .orElse(null);
  }

  @Override
  public void deleteById(final String id) {
    LOGGER.debug("Delete session {}", id);
    Optional.ofNullable(id).filter(this::isSessionIdNotEmpty).ifPresent(sessionStorePort::delete);
  }

  public void deleteExpiredWebSessions() {
    Optional.ofNullable(sessionStorePort.getAll())
        .ifPresent(
            persistentSessions ->
                persistentSessions.forEach(this::deletePersistentSessionIfExpired));
  }

  private void deletePersistentSessionIfExpired(final PersistentSession persistentSession) {
    toWebSession(persistentSession)
        .ifPresentOrElse(
            this::deleteWebSessionIfExpired,
            // otherwise, when the persistent session could
            // not be restored, then delete it.
            () -> deleteById(persistentSession.id()));
  }

  private void deleteWebSessionIfExpired(final WebSession webSession) {
    if (webSession.shouldBeDeleted()) {
      deleteById(webSession.getId());
    }
  }

  private void saveWebSessionIfChanged(final WebSession webSession) {
    if (webSession.isChanged()) {
      LOGGER.debug("Web Session {} changed, save in storage.", webSession);
      sessionStorePort.upsert(webSessionMapper.toPersistentSession(webSession));
      webSession.clearChangeFlag();
    }
  }

  private Optional<WebSession> toWebSession(final PersistentSession persistentSession) {
    return Optional.of(persistentSession).map(webSessionMapper::fromPersistentSession);
  }

  private WebSession getWebSessionIfNotExpired(final PersistentSession persistentSession) {
    final var webSession = toWebSession(persistentSession).orElse(null);
    if (webSession != null && !webSession.shouldBeDeleted()) {
      webSession.suppressTouch(shouldSuppressTouch(request));
      return webSession;
    } else {
      // if session is expired (or has no valid authentication),
      // or the web session could not be restored,
      // then immediately delete the persistent session
      deleteById(persistentSession.id());
      return null;
    }
  }

  /**
   * Whether this request must not extend the session's activity. With {@code
   * camunda.security.session.heartbeat.enabled=false} (the default), unchanged legacy behaviour:
   * suppress only for requests tagged {@code x-is-polling}. With it {@code true}, invert: suppress
   * every request except the recognized heartbeat call, so ordinary application traffic stops
   * counting as activity (ADR-0023).
   */
  private boolean shouldSuppressTouch(final HttpServletRequest request) {
    if (sessionConfiguration.getHeartbeat().isEnabled()) {
      return !isHeartbeatRequest(request);
    }
    return isPollingRequest(request);
  }

  private boolean isPollingRequest(final HttpServletRequest request) {
    boolean isPollingRequest = false;
    try {
      isPollingRequest =
          request != null
              && request.getHeader(POLLING_HEADER) != null
              && Boolean.parseBoolean(request.getHeader(POLLING_HEADER));
    } catch (final Exception e) {
      // This can happen, if it is called outside a dispatcher servlet.
      LOGGER.debug(
          "Cannot access HTTP request outside of a request context; treating as non-polling", e);
    }
    return isPollingRequest;
  }

  private boolean isHeartbeatRequest(final HttpServletRequest request) {
    boolean isHeartbeatRequest = false;
    try {
      isHeartbeatRequest = CamundaSecurityFilterChainConstants.isHeartbeatRequest(request);
    } catch (final Exception e) {
      // This can happen, if it is called outside a dispatcher servlet (e.g. the expiry sweep).
      LOGGER.debug(
          "Cannot access HTTP request outside of a request context; treating as non-heartbeat", e);
    }
    return isHeartbeatRequest;
  }

  private boolean isSessionIdNotEmpty(final String sessionId) {
    return sessionId != null && !sessionId.isEmpty();
  }
}
