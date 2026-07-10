/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context.holder;

import static io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder.CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY;
import static io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder.LAST_REFRESH_ATTR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpSession;

@ExtendWith(MockitoExtension.class)
public class HttpSessionBasedAuthenticationHolderTest {

  @Mock private HttpServletRequest request;
  @Mock private AuthenticationConfiguration authenticationConfiguration;
  private HttpSessionBasedAuthenticationHolder holder;

  @BeforeEach
  void setup() {
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT1S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
  }

  @Test
  public void shouldSupportWhenSessionExists() {
    // given
    final var session = mock(HttpSession.class);
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isTrue();
  }

  @Test
  public void shouldNotSupportWhenSessionDoesNotExist() {
    // given
    when(request.getSession(eq(false))).thenReturn(null);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isFalse();
  }

  @Test
  public void shouldReturnAuthentication() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();

    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(authentication);
  }

  @Test
  public void shouldAddAuthenticationToSession() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = mock(HttpSession.class);

    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.set(authentication);

    // then
    verify(session, times(1))
        .setAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY), eq(authentication));
  }

  @Test
  public void shouldClearAuthenticationFromSession() {
    // given
    final var session = mock(HttpSession.class);
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.clear();

    // then
    verify(session, times(1)).removeAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY));
  }

  @Test
  public void shouldClearAuthenticationAndUpdateLastRefreshWhenIntervalExpires() {
    // given: a session with authentication set and a last-refresh timestamp in the past
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    final var refreshInterval = Duration.ofSeconds(1);
    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(refreshInterval.toString());
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // Backdate beyond the configured interval to simulate deterministic expiry.
    final Instant expiredRefresh = Instant.now().minus(refreshInterval).minusMillis(1);
    session.setAttribute(LAST_REFRESH_ATTR, expiredRefresh);

    // when
    final var result = holder.get();

    // then: authentication is cleared and last-refresh is updated
    assertThat(result).isNull();
    final Instant updatedRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);
    assertThat(updatedRefresh).isAfter(expiredRefresh);
  }

  @Test
  public void shouldReturnAuthenticationWhenWithinRefreshInterval() {
    // given: authentication set and last-refresh is recent
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(authenticationConfiguration.getAuthenticationRefreshInterval()).thenReturn("PT30S");
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);

    // when: retrieved before the interval expires
    final var result = holder.get();

    // then: the cached authentication is returned unchanged
    assertThat(result).isEqualTo(authentication);
  }

  @Test
  public void shouldInitializeRefreshAttributesOnFirstSet() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    holder.set(authentication);

    // then: refresh timestamp is initialized
    assertThat(session.getAttribute(LAST_REFRESH_ATTR)).isInstanceOf(Instant.class);
  }

  @Test
  public void shouldNotReinitializeRefreshAttributesOnSubsequentSet() {
    // given: a session that already has a refresh timestamp
    final var authentication = mock(CamundaAuthentication.class);
    final var session = new MockHttpSession();
    when(request.getSession(eq(false))).thenReturn(session);
    holder.set(authentication);
    final Instant firstRefresh = (Instant) session.getAttribute(LAST_REFRESH_ATTR);

    // when: set is called again
    holder.set(authentication);

    // then: the existing refresh timestamp is not overwritten
    assertThat(session.getAttribute(LAST_REFRESH_ATTR)).isEqualTo(firstRefresh);
  }

  /**
   * Models what a real {@code SessionRepository.findById(id)} returns for concurrent requests
   * against the same session id under Spring Session: two distinct {@link HttpSession} Java objects
   * backed by the same underlying attribute storage (see camunda-security-library#510). The refresh
   * dedup must hold even though {@code synchronized (session)} synchronizes on two different
   * monitors here.
   *
   * <p>Mirrors production wiring, where {@code HttpSessionBasedAuthenticationHolder} is a singleton
   * bean and {@code HttpServletRequest} is a request-scoped proxy: one holder instance is shared by
   * both concurrent requests, each thread resolving its own {@link HttpSession} via a thread-bound
   * {@link ThreadLocal}, exactly as the scoped proxy would.
   */
  @Test
  public void shouldOnlyRefreshOnceAcrossDistinctSessionInstancesForSameSessionId()
      throws Exception {
    // given: two distinct HttpSession objects sharing one backing attribute store, both
    // observing an authentication with an expired last-refresh timestamp
    final var authentication = mock(CamundaAuthentication.class);
    final Map<String, Object> backingStore = new ConcurrentHashMap<>();
    final AtomicInteger refreshCount = new AtomicInteger();
    final var barrier = new CyclicBarrier(2);
    final var awaitedOnce = ThreadLocal.withInitial(() -> false);

    backingStore.put(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY, authentication);
    backingStore.put(LAST_REFRESH_ATTR, Instant.now().minus(Duration.ofSeconds(10)));

    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(Duration.ofMillis(1).toString());

    final var sessionA =
        sharedBackedSession(backingStore, refreshCount, barrier, awaitedOnce, "shared-session-id");
    final var sessionB =
        sharedBackedSession(backingStore, refreshCount, barrier, awaitedOnce, "shared-session-id");

    final ThreadLocal<HttpSession> currentSession = new ThreadLocal<>();
    final var request = mock(HttpServletRequest.class);
    lenient().when(request.getSession(eq(false))).thenAnswer(invocation -> currentSession.get());

    final var sharedHolder =
        new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);

    // when: both requests observe the expired timestamp and race to refresh concurrently
    final ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      final Callable<CamundaAuthentication> callA =
          () -> {
            currentSession.set(sessionA);
            return sharedHolder.get();
          };
      final Callable<CamundaAuthentication> callB =
          () -> {
            currentSession.set(sessionB);
            return sharedHolder.get();
          };
      final Future<CamundaAuthentication> futureA = executor.submit(callA);
      final Future<CamundaAuthentication> futureB = executor.submit(callB);
      futureA.get(5, TimeUnit.SECONDS);
      futureB.get(5, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
      executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    // then: only one of the two concurrent requests actually performed the refresh
    assertThat(refreshCount.get()).isEqualTo(1);
  }

  private static HttpSession sharedBackedSession(
      final Map<String, Object> backingStore,
      final AtomicInteger refreshCount,
      final CyclicBarrier barrier,
      final ThreadLocal<Boolean> awaitedOnce,
      final String sessionId)
      throws Exception {
    final var session = mock(HttpSession.class);
    lenient().when(session.getId()).thenReturn(sessionId);
    lenient()
        .when(session.getAttribute(anyString()))
        .thenAnswer(
            invocation -> {
              final String attributeName = invocation.getArgument(0, String.class);
              if (LAST_REFRESH_ATTR.equals(attributeName) && !awaitedOnce.get()) {
                // force both requests to observe the still-expired timestamp before either
                // has a chance to write the refreshed one, deterministically reproducing the
                // concurrent-refresh race described in camunda-security-library#510
                awaitedOnce.set(true);
                barrier.await(5, TimeUnit.SECONDS);
              }
              return backingStore.get(attributeName);
            });
    lenient()
        .doAnswer(
            invocation -> {
              backingStore.put(invocation.getArgument(0, String.class), invocation.getArgument(1));
              return null;
            })
        .when(session)
        .setAttribute(anyString(), any());
    lenient()
        .doAnswer(
            invocation -> {
              final String attributeName = invocation.getArgument(0, String.class);
              backingStore.remove(attributeName);
              if (CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY.equals(attributeName)) {
                refreshCount.incrementAndGet();
              }
              return null;
            })
        .when(session)
        .removeAttribute(anyString());
    return session;
  }
}
