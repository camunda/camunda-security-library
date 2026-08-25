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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import java.util.concurrent.atomic.AtomicBoolean;
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
    backingStore.put(LAST_REFRESH_ATTR, Instant.now().minus(Duration.ofMinutes(10)));

    // A refresh interval on the order of milliseconds would make this test flaky: `now` is
    // captured independently per thread *before* either reaches the barrier below, so ordinary
    // thread-scheduling jitter between the two captures (executor startup, JIT, GC) can easily
    // exceed a few milliseconds. A 1-second interval keeps that jitter negligible by comparison
    // while the 10-minutes-old seed above is still unambiguously expired against it.
    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(Duration.ofSeconds(1).toString());

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

  /**
   * Production analogue of {@link
   * #shouldOnlyRefreshOnceAcrossDistinctSessionInstancesForSameSessionId}: under Spring Session
   * each concurrent request resolves its own {@link HttpSession} snapshot with its own backing
   * storage, and writes are persisted only at end-of-request {@code save()} — so one request never
   * observes another's in-flight refresh. Dedup therefore cannot lean on any shared session state;
   * it must hold purely through the JVM-local, session-id-keyed guard (ADR-0020).
   */
  @Test
  public void shouldOnlyRefreshOnceAcrossSessionsWithSeparateBackingStoresForSameSessionId()
      throws Exception {
    // given: two HttpSession objects for the same session id, each with its OWN backing store, both
    // observing an authentication with an expired last-refresh timestamp
    final var authentication = mock(CamundaAuthentication.class);
    final Map<String, Object> backingStoreA = new ConcurrentHashMap<>();
    final Map<String, Object> backingStoreB = new ConcurrentHashMap<>();
    final AtomicInteger refreshCount = new AtomicInteger();
    final var barrier = new CyclicBarrier(2);
    final var awaitedOnce = ThreadLocal.withInitial(() -> false);

    final var staleRefresh = Instant.now().minus(Duration.ofMinutes(10));
    backingStoreA.put(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY, authentication);
    backingStoreA.put(LAST_REFRESH_ATTR, staleRefresh);
    backingStoreB.put(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY, authentication);
    backingStoreB.put(LAST_REFRESH_ATTR, staleRefresh);

    // a 1-second interval keeps per-thread scheduling jitter negligible while the 10-minutes-old
    // seed stays unambiguously expired (see the sibling shared-store test for the full rationale).
    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(Duration.ofSeconds(1).toString());

    final var sessionA =
        sharedBackedSession(backingStoreA, refreshCount, barrier, awaitedOnce, "shared-session-id");
    final var sessionB =
        sharedBackedSession(backingStoreB, refreshCount, barrier, awaitedOnce, "shared-session-id");

    final ThreadLocal<HttpSession> currentSession = new ThreadLocal<>();
    final var sharedRequest = mock(HttpServletRequest.class);
    lenient()
        .when(sharedRequest.getSession(eq(false)))
        .thenAnswer(invocation -> currentSession.get());

    final var sharedHolder =
        new HttpSessionBasedAuthenticationHolder(sharedRequest, authenticationConfiguration);

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

    // then: the JVM-local guard alone deduplicated the refresh across the two isolated stores
    assertThat(refreshCount.get()).isEqualTo(1);
  }

  /**
   * When the refresh side effect throws (e.g. the session was invalidated concurrently), the claim
   * advanced inside {@code compute} must be rolled back so a later request can retry the refresh
   * instead of being blocked for the remainder of the cache TTL. Had the claim stuck, the second
   * request's {@code compute} would see a still-current claim and skip, leaving the session
   * un-refreshed until the TTL elapses.
   */
  @Test
  public void shouldRollBackClaimWhenRefreshFailsSoLaterRequestCanRetry() {
    // given: a session whose refresh is due, but the first refresh attempt fails midway
    final var authentication = mock(CamundaAuthentication.class);
    final var refreshInterval = Duration.ofSeconds(1);
    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(refreshInterval.toString());
    holder = new HttpSessionBasedAuthenticationHolder(request, authenticationConfiguration);

    final Instant expiredRefresh = Instant.now().minus(refreshInterval).minusMillis(1);
    final var failFirstRemove = new AtomicBoolean(true);
    final var refreshCount = new AtomicInteger();

    final var session = mock(HttpSession.class);
    when(session.getId()).thenReturn("session-id");
    when(session.getAttribute(LAST_REFRESH_ATTR)).thenReturn(expiredRefresh);
    when(session.getAttribute(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY))
        .thenReturn(authentication);
    doAnswer(
            invocation -> {
              // first attempt throws (as a concurrently-invalidated session would); later ones pass
              if (failFirstRemove.getAndSet(false)) {
                throw new IllegalStateException("session invalidated");
              }
              refreshCount.incrementAndGet();
              return null;
            })
        .when(session)
        .removeAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY));
    when(request.getSession(eq(false))).thenReturn(session);

    // when: the first request refreshes and the refresh side effect throws
    assertThatThrownBy(() -> holder.get()).isInstanceOf(IllegalStateException.class);

    // then: the claim was rolled back, so a following request retries the refresh
    holder.get();
    assertThat(refreshCount.get()).isEqualTo(1);
  }

  /**
   * The claim written by {@code compute()} must not be treated as expired based on how much time
   * has elapsed since it was made: the winner may still be mid-flight (its own session write has
   * not landed yet), and a second, later-arriving request must defer to it rather than re-claim
   * (see camunda-security-library#517).
   *
   * <p>Fully deterministic, no wall-clock waiting: a barrier holds the winner past its claim but
   * before its session write, then the second request runs. The refresh interval is zero, so an
   * elapsed-time predicate would treat the claim as expired the instant it is made — the strongest
   * form of the race — yet the observed-staleness check still defers.
   */
  @Test
  public void shouldNotReclaimWhenWinningClaimHasNotYetWrittenBackToSession() throws Exception {
    // given: a shared session store observed as stale by two requests, and a zero refresh interval
    // so an elapsed-time predicate would consider any claim expired without any time needing to
    // pass
    final var authentication = mock(CamundaAuthentication.class);
    final Map<String, Object> backingStore = new ConcurrentHashMap<>();
    final AtomicInteger refreshCount = new AtomicInteger();
    final var winnerBlocked = new CyclicBarrier(2);
    final var releaseWinner = new CyclicBarrier(2);

    final Instant staleRefresh = Instant.now().minus(Duration.ofMinutes(10));
    backingStore.put(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY, authentication);
    backingStore.put(LAST_REFRESH_ATTR, staleRefresh);

    when(authenticationConfiguration.getAuthenticationRefreshInterval())
        .thenReturn(Duration.ZERO.toString());

    final var sessionA =
        blockingSharedBackedSession(
            backingStore, refreshCount, winnerBlocked, releaseWinner, "shared-session-id");
    final var sessionB = sharedBackedSession(backingStore, refreshCount, "shared-session-id");

    final ThreadLocal<HttpSession> currentSession = new ThreadLocal<>();
    final var sharedRequest = mock(HttpServletRequest.class);
    lenient()
        .when(sharedRequest.getSession(eq(false)))
        .thenAnswer(invocation -> currentSession.get());
    final var sharedHolder =
        new HttpSessionBasedAuthenticationHolder(sharedRequest, authenticationConfiguration);

    final ExecutorService executor = Executors.newFixedThreadPool(1);
    try {
      // when: thread A wins the claim and blocks before writing it back to the session
      final Future<?> futureA =
          executor.submit(
              () -> {
                currentSession.set(sessionA);
                sharedHolder.get();
              });
      winnerBlocked.await(5, TimeUnit.SECONDS);

      // A has claimed but is blocked before writing its refresh back; thread B now observes the
      // same still-stale session and must defer to A's claim, not reclaim it
      currentSession.set(sessionB);
      sharedHolder.get();

      releaseWinner.await(5, TimeUnit.SECONDS);
      futureA.get(5, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
      executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    // then: only the original winner performed the refresh
    assertThat(refreshCount.get()).isEqualTo(1);
  }

  private static HttpSession blockingSharedBackedSession(
      final Map<String, Object> backingStore,
      final AtomicInteger refreshCount,
      final CyclicBarrier winnerBlocked,
      final CyclicBarrier releaseWinner,
      final String sessionId)
      throws Exception {
    final var session = sharedBackedSession(backingStore, refreshCount, sessionId);
    doAnswer(
            invocation -> {
              winnerBlocked.await(5, TimeUnit.SECONDS);
              releaseWinner.await(5, TimeUnit.SECONDS);
              backingStore.remove(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY);
              refreshCount.incrementAndGet();
              return null;
            })
        .when(session)
        .removeAttribute(eq(CAMUNDA_AUTHENTICATION_SESSION_HOLDER_KEY));
    return session;
  }

  private static HttpSession sharedBackedSession(
      final Map<String, Object> backingStore,
      final AtomicInteger refreshCount,
      final String sessionId) {
    final var session = mock(HttpSession.class);
    lenient().when(session.getId()).thenReturn(sessionId);
    lenient()
        .when(session.getAttribute(anyString()))
        .thenAnswer(invocation -> backingStore.get(invocation.getArgument(0, String.class)));
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
                // capture the still-expired value before awaiting the barrier: once released,
                // scheduling may let one thread run to completion (including writing the
                // refreshed value back into the shared backingStore) before the other thread's
                // post-barrier code even resumes, so reading backingStore only after the barrier
                // would make the race non-deterministic under a skewed schedule
                awaitedOnce.set(true);
                final Object capturedValue = backingStore.get(attributeName);
                barrier.await(5, TimeUnit.SECONDS);
                return capturedValue;
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
