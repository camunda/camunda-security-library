/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

import io.camunda.security.api.model.config.SessionConfiguration;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.session.WebSessionMapper.SpringBasedWebSessionAttributeConverter;
import io.camunda.security.spring.session.WebSessionRepository.ExpiryCheck;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.session.MapSession;
import org.springframework.session.Session;

@ExtendWith(MockitoExtension.class)
class WebSessionRepositoryTest {

  private static final Instant EXPIRED_LAST_ACCESS =
      Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds() * 2);

  private WebSessionRepository webSessionRepository;
  private SessionStorePort sessionStore;
  private SessionConfiguration sessionConfiguration;
  private WebSessionMapper webSessionMapper;

  @Mock private HttpServletRequest request;

  @BeforeEach
  void setUp() {
    sessionStore = new SessionStorePortStub();
    sessionConfiguration = new SessionConfiguration();
    webSessionMapper =
        new WebSessionMapper(
            new SpringBasedWebSessionAttributeConverter(new GenericConversionService()));
    webSessionRepository =
        new WebSessionRepository(sessionStore, webSessionMapper, request, sessionConfiguration);
  }

  @Test
  void createSessionReturnSession() {
    // when
    final var webSession = webSessionRepository.createSession();

    // then
    assertThat(webSession).isNotNull();
    assertThat(webSession.getId()).isNotNull();
    assertThat(webSession.getLastAccessedTime()).isNotNull();
    assertThat(webSession.getCreationTime()).isNotNull();
    assertThat(webSession.getMaxInactiveInterval()).isNotNull();
  }

  @Test
  void createSessionAppliesConfiguredMaxInactiveInterval() {
    // given
    sessionConfiguration.setMaxInactiveInterval(Duration.ofMinutes(45));

    // when
    final var webSession = webSessionRepository.createSession();

    // then
    assertThat(webSession.getMaxInactiveInterval()).isEqualTo(Duration.ofMinutes(45));
  }

  @Test
  void findByIdSuppressesTouchForPollingRequestWhenHeartbeatDisabled() {
    // given
    when(request.getHeader("x-is-polling")).thenReturn("true");
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    final var found = webSessionRepository.findById(webSession.getId());

    // then
    assertThat(found).isNotNull();
    assertThat(found.isTouchSuppressed()).isTrue();
  }

  @Test
  void findByIdDoesNotSuppressTouchForOrdinaryRequestWhenHeartbeatDisabled() {
    // given
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    final var found = webSessionRepository.findById(webSession.getId());

    // then
    assertThat(found).isNotNull();
    assertThat(found.isTouchSuppressed()).isFalse();
  }

  @Test
  void findByIdSuppressesTouchForOrdinaryRequestWhenHeartbeatEnabled() {
    // given: getMethod() alone determines the outcome here — isHeartbeatRequest short-circuits on
    // the method check before ever consulting getRequestURI().
    sessionConfiguration.getHeartbeat().setEnabled(true);
    when(request.getMethod()).thenReturn("GET");
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    final var found = webSessionRepository.findById(webSession.getId());

    // then
    assertThat(found).isNotNull();
    assertThat(found.isTouchSuppressed()).isTrue();
  }

  @Test
  void findByIdDoesNotSuppressTouchForHeartbeatRequestWhenHeartbeatEnabled() {
    // given
    sessionConfiguration.getHeartbeat().setEnabled(true);
    when(request.getMethod()).thenReturn("POST");
    when(request.getRequestURI()).thenReturn("/operate/session/heartbeat");
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    final var found = webSessionRepository.findById(webSession.getId());

    // then
    assertThat(found).isNotNull();
    assertThat(found.isTouchSuppressed()).isFalse();
  }

  @Test
  void saveValidSessionPersistsSession() {
    // given
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());

    // when
    webSessionRepository.save(webSession);

    // then
    assertThat(webSessionRepository.findById(webSession.getId())).isNotNull();
  }

  @Test
  void saveExpiredSessionDeleteSession() {
    // given
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    webSession.setLastAccessedTime(
        Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds() * 2));
    webSessionRepository.save(webSession);

    // then
    assertThat(webSessionRepository.findById(webSession.getId())).isNull();
  }

  @Test
  void findByNotExistingIdReturnsNull() {
    assertThat(webSessionRepository.findById("not-existing-id")).isNull();
  }

  @Test
  void deleteById() {
    // given
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSessionRepository.save(webSession);

    // when
    webSessionRepository.deleteById(webSession.getId());

    // then
    assertThat(webSessionRepository.findById(webSession.getId())).isNull();
  }

  @Test
  void saveSessionWithLockAndRefreshAttributePersistsSession() {
    // given
    final var webSession = webSessionRepository.createSession();
    webSession.setLastAccessedTime(Instant.now());
    webSession.setAttribute("lock", webSession.getId() + "LOCK");
    webSession.setAttribute("refresh", Instant.now());

    // when
    webSessionRepository.save(webSession);

    // then
    assertThat(webSessionRepository.findById(webSession.getId())).isNotNull();
  }

  @Test
  void deleteExpiredWebSessions() {
    // given
    final var expiredLastAccessedTime =
        Instant.now().minusSeconds(MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds() * 2);
    sessionStore.upsert(
        new PersistentSession(
            "s1",
            expiredLastAccessedTime.toEpochMilli(),
            expiredLastAccessedTime.toEpochMilli(),
            MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds(),
            Map.of()));
    sessionStore.upsert(
        new PersistentSession(
            "s2",
            expiredLastAccessedTime.toEpochMilli(),
            expiredLastAccessedTime.toEpochMilli(),
            MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds(),
            Map.of()));
    sessionStore.upsert(
        new PersistentSession(
            "s3",
            expiredLastAccessedTime.toEpochMilli(),
            expiredLastAccessedTime.toEpochMilli(),
            MapSession.DEFAULT_MAX_INACTIVE_INTERVAL.toSeconds(),
            Map.of()));

    assertThat(sessionStore.getAll()).hasSize(3);

    // when
    webSessionRepository.deleteExpiredWebSessions();

    // then
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void deleteExpiredWebSessionsHandsEachExpiredSessionToTheHandlerBeforeDeletingIt() {
    // given
    final List<String> handedOver = new ArrayList<>();
    final List<Integer> storedWhenHandedOver = new ArrayList<>();
    final var repository =
        repositoryWithHandler(
            session -> {
              handedOver.add(session.getId());
              storedWhenHandedOver.add(sessionStore.getAll().size());
            });
    storeSession(repository, EXPIRED_LAST_ACCESS);

    // when
    repository.deleteExpiredWebSessions();

    // then
    assertThat(handedOver).hasSize(1);
    assertThat(storedWhenHandedOver).containsExactly(1);
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void deleteExpiredWebSessionsDoesNotHandLiveSessionsToTheHandler() {
    // given
    final List<Session> handedOver = new ArrayList<>();
    final var repository = repositoryWithHandler(handedOver::add);
    storeSession(repository, Instant.now());

    // when
    repository.deleteExpiredWebSessions();

    // then
    assertThat(handedOver).isEmpty();
    assertThat(sessionStore.getAll()).hasSize(1);
  }

  @Test
  void deleteExpiredWebSessionsStillDeletesTheSessionWhenTheHandlerFails() {
    // given
    final var repository =
        repositoryWithHandler(
            session -> {
              throw new IllegalStateException("revocation failed");
            });
    storeSession(repository, EXPIRED_LAST_ACCESS);

    // when
    repository.deleteExpiredWebSessions();

    // then
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void findByIdHandsAnExpiredSessionToTheHandlerAndDeletesIt() {
    // given
    final List<Session> handedOver = new ArrayList<>();
    final var repository = repositoryWithHandler(handedOver::add);
    final var stored = storeSession(repository, EXPIRED_LAST_ACCESS);

    // when
    final var found = repository.findById(stored.getId());

    // then
    assertThat(found).isNull();
    assertThat(handedOver).extracting(Session::getId).containsExactly(stored.getId());
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void saveHandsASessionThatExpiredDuringTheRequestToTheHandlerAndDeletesIt() {
    // given - a request loaded the session while it was live
    final List<Session> handedOver = new ArrayList<>();
    final var repository = repositoryWithHandler(handedOver::add);
    final var webSession = storeSession(repository, Instant.now());

    // when - the request saves it after its idle deadline
    webSession.setLastAccessedTime(EXPIRED_LAST_ACCESS);
    repository.save(webSession);

    // then
    assertThat(handedOver).extracting(Session::getId).containsExactly(webSession.getId());
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void findByIdDoesNotHandASessionWithAnInvalidatedAuthenticationToTheHandler() {
    // given - deleted because its authentication was invalidated, not because it expired
    final List<Session> handedOver = new ArrayList<>();
    final var repository = repositoryWithHandler(handedOver::add);
    final var authentication = new TestingAuthenticationToken("user", "credentials");
    authentication.setAuthenticated(false);
    final var stored = repository.createSession();
    stored.setLastAccessedTime(Instant.now());
    stored.setAttribute(SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(authentication));
    sessionStore.upsert(webSessionMapper.toPersistentSession(stored));

    // when
    final var found = repository.findById(stored.getId());

    // then
    assertThat(found).isNull();
    assertThat(handedOver).isEmpty();
    assertThat(sessionStore.getAll()).isEmpty();
  }

  @Test
  void handsTheHandlerWhereTheExpiryWasFound() {
    // given
    final List<ExpiryCheck> checks = new ArrayList<>();
    final var repository =
        new WebSessionRepository(
            sessionStore,
            webSessionMapper,
            request,
            sessionConfiguration,
            (session, check) -> checks.add(check));
    final var foundByRequest = storeSession(repository, EXPIRED_LAST_ACCESS);
    repository.findById(foundByRequest.getId());
    final var savedByRequest = storeSession(repository, Instant.now());
    savedByRequest.setLastAccessedTime(EXPIRED_LAST_ACCESS);
    repository.save(savedByRequest);
    storeSession(repository, EXPIRED_LAST_ACCESS);

    // when
    repository.deleteExpiredWebSessions();

    // then the sweep can wait on the handler, a request must not
    assertThat(checks).containsExactly(ExpiryCheck.REQUEST, ExpiryCheck.REQUEST, ExpiryCheck.SWEEP);
  }

  private WebSessionRepository repositoryWithHandler(final Consumer<Session> handler) {
    return new WebSessionRepository(
        sessionStore,
        webSessionMapper,
        request,
        sessionConfiguration,
        (session, check) -> handler.accept(session));
  }

  /** Writes the session straight to the store, so an expired one is not deleted on save. */
  private WebSession storeSession(
      final WebSessionRepository repository, final Instant lastAccessedTime) {
    final var webSession = repository.createSession();
    webSession.setLastAccessedTime(lastAccessedTime);
    sessionStore.upsert(webSessionMapper.toPersistentSession(webSession));
    return webSession;
  }

  static final class SessionStorePortStub implements SessionStorePort {

    private final Map<String, PersistentSession> sessions = new HashMap<>();

    @Override
    public PersistentSession get(final String sessionId) {
      return sessions.get(sessionId);
    }

    @Override
    public void upsert(final PersistentSession session) {
      sessions.put(session.id(), session);
    }

    @Override
    public void delete(final String sessionId) {
      sessions.remove(sessionId);
    }

    @Override
    public List<PersistentSession> getAll() {
      return new ArrayList<>(sessions.values());
    }
  }
}
