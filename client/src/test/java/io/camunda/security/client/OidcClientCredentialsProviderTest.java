/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import io.camunda.security.client.OutboundCredentialsProvider.StatusCode;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OidcClientCredentialsProviderTest {

  private static final String SECRET = "s3cr3t-value";

  private TokenEndpoint endpoint;
  private MutableClock clock;

  @BeforeEach
  void setUp() throws IOException {
    endpoint = new TokenEndpoint();
    clock = new MutableClock();
  }

  @AfterEach
  void tearDown() {
    endpoint.close();
  }

  private OidcClientCredentialsProvider provider(
      final String audience, final List<String> scopes, final String resource) {
    final var config =
        new OidcClientCredentialsConfiguration(
            endpoint.uri(), "my-client", SECRET, audience, scopes, resource, null, null);
    return new OidcClientCredentialsProvider(config, clock);
  }

  private OidcClientCredentialsProvider provider(final URI tokenUri, final Clock tokenClock) {
    final var config =
        new OidcClientCredentialsConfiguration(
            tokenUri, "my-client", SECRET, null, null, null, null, null);
    return new OidcClientCredentialsProvider(config, tokenClock);
  }

  private OidcClientCredentialsProvider provider(
      final Duration connectTimeout, final Duration readTimeout) {
    final var config =
        new OidcClientCredentialsConfiguration(
            endpoint.uri(), "my-client", SECRET, null, null, null, connectTimeout, readTimeout);
    return new OidcClientCredentialsProvider(config, clock);
  }

  /** No message in the cause chain may contain any of the given texts. */
  private static void assertNoneOfTheMessagesContains(
      final Throwable failure, final String... texts) {
    for (Throwable t = failure; t != null; t = t.getCause()) {
      assertThat(String.valueOf(t.getMessage())).doesNotContain(texts);
    }
  }

  /** Waits until the endpoint has received the given number of token requests. */
  private void awaitRequests(final int expected) throws InterruptedException {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (endpoint.requestCount() < expected) {
      assertThat(System.nanoTime()).as("token request did not arrive").isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(5);
    }
  }

  private static TokenRequestException failureOf(final Future<?> result) throws Exception {
    try {
      result.get(10, TimeUnit.SECONDS);
    } catch (final ExecutionException e) {
      assertThat(e.getCause()).isInstanceOf(TokenRequestException.class);
      return (TokenRequestException) e.getCause();
    }
    throw new AssertionError("expected the call to fail");
  }

  private OidcClientCredentialsProvider provider() {
    return provider(null, null, null);
  }

  private static String authorization(final OutboundCredentialsProvider provider)
      throws IOException {
    final List<String> values = new ArrayList<>();
    provider.applyCredentials((header, value) -> values.add(header + "=" + value));
    return values.getFirst();
  }

  @Test
  void fetchesTokenAndSetsBearerHeader() throws IOException {
    assertThat(authorization(provider())).isEqualTo("Authorization=Bearer token-1");
  }

  @Test
  void sendsReservedParametersAndOptionalOnes() throws IOException {
    authorization(provider("hub-api", List.of("read", "write"), "https://hub"));

    assertThat(endpoint.requestBodies()).hasSize(1);
    assertThat(endpoint.requestBodies().getFirst().split("&"))
        .containsExactlyInAnyOrder(
            "grant_type=client_credentials",
            "client_id=my-client",
            "client_secret=" + SECRET,
            "audience=hub-api",
            "scope=read+write",
            "resource=https%3A%2F%2Fhub");
  }

  @Test
  void omitsOptionalParametersWhenUnset() throws IOException {
    authorization(provider());

    assertThat(endpoint.requestBodies().getFirst())
        .doesNotContain("audience")
        .doesNotContain("scope")
        .doesNotContain("resource");
  }

  @Test
  void secondCallUsesCachedToken() throws IOException {
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo(authorization(provider));
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void refreshesBeforeTheTokenExpires() throws IOException {
    final var provider = provider();
    authorization(provider);

    clock.advance(Duration.ofSeconds(3600 - 31));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofSeconds(2));
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedFetchesANewTokenAndAsksForRetry() throws IOException {
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isTrue();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedMayBeReportedOnAnotherThreadThanTheOneThatApplied() throws Exception {
    final var provider = provider();
    final ExecutorService other = Executors.newSingleThreadExecutor();
    try {
      authorization(provider);

      final Future<Boolean> retry =
          other.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));

      assertThat(retry.get(10, TimeUnit.SECONDS)).isTrue();
      assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    } finally {
      other.shutdownNow();
    }
  }

  @Test
  void unauthorizedWithTheSameTokenAgainDoesNotAskForRetry() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"fixed\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedWhenTheIdpFailsDoesNotAskForRetryAndDoesNotThrow() throws IOException {
    final var provider = provider();
    authorization(provider);
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
  }

  @Test
  void otherStatusesKeepTheTokenAndDoNotRetry() throws IOException {
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(403))).isFalse();
    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(500))).isFalse();

    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void concurrentCallersShareOneTokenRequest() throws Exception {
    final var provider = provider();
    final int callers = 8;
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(callers);
    try {
      final List<Future<String>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        results.add(pool.submit(() -> authorization(provider)));
      }
      pool.awaitAllWaiting();
      release.countDown();

      for (final Future<String> result : results) {
        assertThat(result.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
      }
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void concurrentUnauthorizedReportsShareOneTokenRequest() throws Exception {
    final var provider = provider();
    authorization(provider);
    final int callers = 8;
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(callers);
    try {
      final List<Future<Boolean>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        results.add(pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401))));
      }
      pool.awaitAllWaiting();
      release.countDown();

      for (final Future<Boolean> result : results) {
        assertThat(result.get(10, TimeUnit.SECONDS)).isTrue();
      }
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void concurrentCallersShareTheFailureOfOneTokenRequestEachWithItsOwnException() throws Exception {
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");
    final var provider = provider();
    final int callers = 8;
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(callers);
    try {
      final List<Future<String>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        results.add(pool.submit(() -> authorization(provider)));
      }
      pool.awaitAllWaiting();
      release.countDown();

      final Set<TokenRequestException> failures =
          Collections.newSetFromMap(new IdentityHashMap<>());
      for (final Future<String> result : results) {
        final TokenRequestException failure = failureOf(result);
        assertThat(failure.getStatus()).isEqualTo(503);
        assertThat(failure.getError()).isEqualTo("temporarily_unavailable");
        assertThat(failure.getMessage()).contains("my-client");
        failures.add(failure);
      }
      assertThat(failures).hasSize(callers);
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void unauthorizedWaitingForARefreshInFlightUsesItsResult() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3600));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> refresh = pool.submit(() -> authorization(provider));
      awaitRequests(2);
      final Future<Boolean> retry =
          pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(refresh.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-2");
      assertThat(retry.get(10, TimeUnit.SECONDS)).isTrue();
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void unauthorizedWaitingForAFailingRefreshDoesNotAskForRetry() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3600));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> refresh = pool.submit(() -> authorization(provider));
      awaitRequests(2);
      final Future<Boolean> retry =
          pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(failureOf(refresh).getStatus()).isEqualTo(503);
      assertThat(retry.get(10, TimeUnit.SECONDS)).isFalse();
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void waiterAfterAnUncacheableTokenSharesIt() throws Exception {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}");
    final var provider = provider();
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      awaitRequests(1);
      final Future<String> waiter = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer abc");
      assertThat(waiter.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer abc");
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void unauthorizedAfterAnUncacheableTokenAsksForRetryWithoutAnExtraTokenRequest()
      throws IOException {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}");
    final var provider = provider();
    authorization(provider);

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isTrue();
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void connectionRefusedFailsWithoutAResponseStatus() throws IOException {
    final URI closed;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      closed = URI.create("http://127.0.0.1:" + socket.getLocalPort() + "/token");
    }
    final var provider = provider(closed, clock);

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e.getError()).isNull();
              assertThat(e.getMessage()).contains("my-client").doesNotContain(SECRET);
              assertThat(e).hasCauseInstanceOf(IOException.class);
            });
  }

  @Test
  void transportFailureHidesTheQueryOfTheTokenUriInTheWholeCauseChain() throws IOException {
    final URI closed;
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      closed = URI.create("http://127.0.0.1:" + socket.getLocalPort() + "/token?key=qs-secret");
    }
    final var provider = provider(closed, clock);

    final Throwable failure = catchThrowable(() -> authorization(provider));

    assertThat(failure).isInstanceOf(TokenRequestException.class);
    for (Throwable t = failure; t != null; t = t.getCause()) {
      assertThat(String.valueOf(t.getMessage())).doesNotContain("qs-secret");
    }
    assertThat(failure.getMessage()).contains("127.0.0.1:" + closed.getPort() + "/token");
  }

  @Test
  void expiryCountsFromTheTimeTheRequestWasSent() throws Exception {
    final var provider = provider();
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(1);
    try {
      final Future<String> first = pool.submit(() -> authorization(provider));
      awaitRequests(1);
      clock.advance(Duration.ofSeconds(3600));
      release.countDown();
      assertThat(first.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void unauthorizedWhenTheRefreshFailsDropsTheRejectedToken() throws IOException {
    final var provider = provider();
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();

    endpoint.respondWith(
        200, "{\"access_token\":\"fresh\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer fresh");
    assertThat(endpoint.requestCount()).isEqualTo(3);
  }

  @Test
  void failedRefreshKeepsSendingTheOldTokenUntilItExpires() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    assertThat(endpoint.requestCount()).isEqualTo(2);

    clock.advance(Duration.ofSeconds(11));
    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class, e -> assertThat(e.getStatus()).isEqualTo(503));
  }

  @Test
  void failedRefreshAfterUnauthorizedDoesNotSendTheRejectedToken() throws IOException {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");

    assertThat(provider.shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();

    assertThatThrownBy(() -> authorization(provider)).isInstanceOf(TokenRequestException.class);
  }

  @Test
  void waiterThatSharesAFailureOfAnotherCallerDoesNotDropTheOldToken() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      awaitRequests(2);
      final Future<String> waiter = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
      assertThat(waiter.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
      assertThat(endpoint.requestCount()).isEqualTo(2);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void unauthorizedWaiterOnAFailingRefreshDropsTheRejectedToken() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    endpoint.respondWith(503, "{\"error\":\"temporarily_unavailable\"}");
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> refresh = pool.submit(() -> authorization(provider));
      awaitRequests(2);
      final Future<Boolean> retry =
          pool.submit(() -> provider.shouldRetryRequest(StatusCode.ofHttp(401)));
      pool.awaitAllWaiting();
      release.countDown();

      assertThat(retry.get(10, TimeUnit.SECONDS)).isFalse();
      // The refreshing caller may read the token before the waiter drops it, so its result is open.
      try {
        refresh.get(10, TimeUnit.SECONDS);
      } catch (final ExecutionException e) {
        assertThat(e.getCause()).isInstanceOf(TokenRequestException.class);
      }
    } finally {
      release.countDown();
      pool.shutdownNow();
    }

    assertThatThrownBy(() -> authorization(provider)).isInstanceOf(TokenRequestException.class);
  }

  @Test
  void refreshStartsExactlyAtRefreshAt() throws IOException {
    final var provider = provider();
    final Instant sentAt = clock.instant();
    authorization(provider);
    final Instant refreshAt = sentAt.plusSeconds(3600).minusSeconds(Math.min(30, 3600 / 2));

    clock.advance(Duration.between(clock.instant(), refreshAt).minusNanos(1));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofNanos(1));
    assertThat(clock.instant()).isEqualTo(refreshAt);
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-2");
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @ParameterizedTest
  @ValueSource(strings = {"abc\\r\\ndef", "abc\\u0000x", "a b"})
  void accessTokenWithCharactersThatAreNotAllowedInAHeaderFails(final String accessToken) {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("characters that are not allowed in a header");
    assertNoneOfTheMessagesContains(failure, "abc");
  }

  @Test
  void unexpectedRuntimeExceptionFailsAsTokenRequestExceptionAndTheNextCallFetchesAgain()
      throws IOException {
    final ThrowingClock throwingClock = new ThrowingClock();
    final var provider = provider(endpoint.uri(), throwingClock);
    throwingClock.arm();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(TokenRequestException.NO_RESPONSE);
              assertThat(e).hasCauseInstanceOf(IllegalStateException.class);
            });

    throwingClock.disarm();
    // The clock fails before the request is sent, so the endpoint issues its first token only now.
    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void overflowingExpiresInReturnsTheTokenWithoutCachingIt() throws IOException {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":"
            + Long.MAX_VALUE
            + "}");
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer abc");
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void readTimeoutEndsABlockedTokenRequest() throws Exception {
    final var provider = provider(null, Duration.ofMillis(200));
    final CountDownLatch release = endpoint.blockResponses();
    try {
      final Throwable failure = catchThrowable(() -> authorization(provider));

      assertThat(failure).isInstanceOf(TokenRequestException.class);
      assertThat(((TokenRequestException) failure).getStatus())
          .isEqualTo(TokenRequestException.NO_RESPONSE);
      assertThat(failure).hasMessageContaining("my-client").hasCauseInstanceOf(IOException.class);
      assertThat(endpoint.requestCount()).isEqualTo(1);
    } finally {
      release.countDown();
    }
  }

  @Test
  void aTimeoutBelowOneMillisecondStillTimesOut() {
    final var provider = provider(null, Duration.ofNanos(500_000));
    final CountDownLatch release = endpoint.blockResponses();
    try {
      assertThatThrownBy(() -> authorization(provider))
          .isInstanceOf(TokenRequestException.class)
          .hasCauseInstanceOf(IOException.class);
    } finally {
      release.countDown();
    }
  }

  @Test
  void requestAsksForJsonAndKeepsTheQueryOfTheTokenUri() throws IOException {
    final var config =
        new OidcClientCredentialsConfiguration(
            URI.create(endpoint.uri() + "?p=policy"),
            "my-client",
            SECRET,
            null,
            null,
            null,
            null,
            null);

    authorization(new OidcClientCredentialsProvider(config, clock));

    assertThat(endpoint.acceptHeaders()).containsExactly("application/json");
    assertThat(endpoint.requestQueries()).containsExactly("p=policy");
  }

  @Test
  void successResponseThatIsNotJsonFails() {
    endpoint.respondWithContentType("text/plain");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "token-1");
  }

  @Test
  void closeIsANoOpAndTheProviderStillWorks() throws IOException {
    final var provider = provider();

    provider.close();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer token-1");
  }

  @ParameterizedTest
  @ValueSource(strings = {"\"\"", "\"  \"", "null"})
  void blankTokenTypeFails(final String tokenType) {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":" + tokenType + ",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc");
  }

  @Test
  void missingTokenTypeFails() {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable")
        .hasMessageContaining("token_type")
        .hasNoCause();
    assertNoneOfTheMessagesContains(failure, "abc");
  }

  @Test
  void interruptedWaiterFailsWithIoExceptionAndKeepsTheInterruptFlag() throws Exception {
    final var provider = provider();
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      final AtomicBoolean flagKept = new AtomicBoolean();
      final Future<String> waiter =
          pool.submit(
              () -> {
                try {
                  return authorization(provider);
                } finally {
                  flagKept.set(Thread.currentThread().isInterrupted());
                }
              });
      pool.awaitAllWaiting();
      pool.threads().getLast().interrupt();

      assertThatThrownBy(() -> waiter.get(10, TimeUnit.SECONDS))
          .hasCauseInstanceOf(IOException.class)
          .hasMessageContaining("Interrupted")
          .hasMessageContaining("my-client");
      assertThat(flagKept).isTrue();

      release.countDown();
      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-1");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void interruptedWaiterFailsEvenWhileTheOldTokenIsValid() throws Exception {
    final var provider = provider();
    authorization(provider);
    clock.advance(Duration.ofSeconds(3590));
    final CountDownLatch release = endpoint.blockResponses();
    final Callers pool = new Callers(2);
    try {
      final Future<String> fetcher = pool.submit(() -> authorization(provider));
      pool.awaitAllWaiting();
      final AtomicBoolean flagKept = new AtomicBoolean();
      final Future<String> waiter =
          pool.submit(
              () -> {
                try {
                  return authorization(provider);
                } finally {
                  flagKept.set(Thread.currentThread().isInterrupted());
                }
              });
      pool.awaitAllWaiting();
      pool.threads().getLast().interrupt();

      assertThatThrownBy(() -> waiter.get(10, TimeUnit.SECONDS))
          .hasCauseInstanceOf(IOException.class)
          .hasMessageContaining("Interrupted")
          .hasMessageContaining("my-client");
      assertThat(flagKept).isTrue();

      release.countDown();
      assertThat(fetcher.get(10, TimeUnit.SECONDS)).isEqualTo("Authorization=Bearer token-2");
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void errorResponseFailsWithoutLeakingTheSecret() {
    endpoint.respondWith(
        401, "{\"error\":\"invalid_client\",\"error_description\":\"bad credentials\"}");
    final var provider = provider();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(401);
              assertThat(e.getError()).isEqualTo("invalid_client");
              assertThat(e.getErrorDescription()).isEqualTo("bad credentials");
              assertThat(e.getMessage()).contains("my-client").doesNotContain(SECRET);
            });
  }

  @Test
  void nonJsonErrorResponseStillFailsWithStatus() {
    endpoint.respondWith(503, "<html>unavailable</html>");
    final var provider = provider();

    assertThatThrownBy(() -> authorization(provider))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e.getStatus()).isEqualTo(503);
              assertThat(e.getError()).isNull();
            });
  }

  @Test
  void responseWithoutAccessTokenFails() {
    endpoint.respondWith(200, "{\"token_type\":\"Bearer\",\"expires_in\":60}");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              assertThat(e).hasNoCause();
              assertThat(e.getMessage()).contains("not usable").contains("access_token");
            });
  }

  @Test
  void invalidJsonResponseFails() {
    endpoint.respondWith(200, "not json");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("is not usable: Invalid JSON");
  }

  @Test
  void invalidJsonResponseHasNoCauseAndDoesNotQuoteTheBody() {
    endpoint.respondWith(200, "{\"access_token\":\"leaky-token\" oops");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure).isInstanceOf(TokenRequestException.class).hasNoCause();
    assertThat(failure.getMessage()).contains("is not usable: Invalid JSON");
    assertNoneOfTheMessagesContains(failure, "leaky-token", "oops");
  }

  @Test
  void errorResponseWithLineBreaksIsSanitized() {
    endpoint.respondWith(
        400, "{\"error\":\"bad\\r\\nforged\",\"error_description\":\"a\\nb\\r\\u2028c\"}");

    assertThatThrownBy(() -> authorization(provider()))
        .isInstanceOfSatisfying(
            TokenRequestException.class,
            e -> {
              // Nimbus drops an error code with illegal characters and strips them from the
              // description; sanitize() covers anything it lets through.
              assertThat(e.getError()).isNull();
              assertThat(e.getErrorDescription()).isEqualTo("abc");
              assertThat(e.getMessage()).doesNotContain("\r", "\n", "\u2028");
            });
  }

  @Test
  void parseMessageThatQuotesItsCauseIsWithheld() {
    final var quoting =
        new ParseException(
            "Unexpected exception: leaky-token", new IllegalStateException("leaky-token"));
    final var naming = new ParseException("Missing JSON object member with key access_token");

    assertThat(OidcClientCredentialsProvider.describe(quoting))
        .isEqualTo("the response cannot be parsed");
    assertThat(OidcClientCredentialsProvider.describe(naming))
        .isEqualTo("Missing JSON object member with key access_token");
  }

  @ParameterizedTest
  @ValueSource(strings = {"true", "123", "\"  \"", "null", "{}"})
  void accessTokenThatIsNotANonBlankStringFails(final String accessToken) {
    endpoint.respondWith(
        200, "{\"access_token\":" + accessToken + ",\"token_type\":\"Bearer\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "123");
  }

  @Test
  void tokenWithoutExpiresInIsNotCached() throws IOException {
    endpoint.respondWith(200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\"}");
    final var provider = provider();

    assertThat(authorization(provider)).isEqualTo("Authorization=Bearer abc");
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void shortLivedTokenIsRefreshedHalfwayThroughItsLifetime() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":20}");
    final var provider = provider();
    authorization(provider);

    clock.advance(Duration.ofSeconds(9));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(1);

    clock.advance(Duration.ofSeconds(2));
    authorization(provider);
    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @Test
  void expiresInAsNumericStringIsCached() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":\"3599\"}");
    final var provider = provider();

    authorization(provider);
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(1);
  }

  @Test
  void zeroExpiresInIsNotCached() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":0}");
    final var provider = provider();

    authorization(provider);
    authorization(provider);

    assertThat(endpoint.requestCount()).isEqualTo(2);
  }

  @ParameterizedTest
  @ValueSource(strings = {"\"abc\"", "\" 3599 \"", "-5", "\"\"", "null", "true"})
  void invalidExpiresInFails(final String expiresIn) {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc-secret\",\"token_type\":\"Bearer\",\"expires_in\":"
            + expiresIn
            + "}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc-secret");
  }

  @Test
  void dpopTokenTypeIsSentAsDpop() throws IOException {
    endpoint.respondWith(
        200, "{\"access_token\":\"abc\",\"token_type\":\"DPoP\",\"expires_in\":60}");

    assertThat(authorization(provider())).isEqualTo("Authorization=DPoP abc");
  }

  @ParameterizedTest
  @ValueSource(strings = {"mac", "N_A"})
  void otherTokenTypesFail(final String tokenType) {
    endpoint.respondWith(
        200,
        "{\"access_token\":\"abc-secret\",\"token_type\":\"" + tokenType + "\",\"expires_in\":60}");

    final Throwable failure = catchThrowable(() -> authorization(provider()));

    assertThat(failure)
        .isInstanceOf(TokenRequestException.class)
        .hasMessageContaining("not usable");
    assertNoneOfTheMessagesContains(failure, "abc-secret");
  }

  /** A clock that fails once armed; the provider reads it before it sends a token request. */
  private static final class ThrowingClock extends Clock {
    private volatile boolean armed;

    void arm() {
      armed = true;
    }

    void disarm() {
      armed = false;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      if (armed) {
        throw new IllegalStateException("clock failure");
      }
      return Instant.parse("2026-01-01T00:00:00Z");
    }
  }

  /** Pool with one thread per caller, so a test can tell when every caller is parked. */
  private static final class Callers {
    private final List<Thread> threads = new CopyOnWriteArrayList<>();
    private final ExecutorService executor;

    Callers(final int size) {
      executor =
          Executors.newFixedThreadPool(
              size,
              runnable -> {
                final Thread thread = new Thread(runnable);
                threads.add(thread);
                return thread;
              });
    }

    <T> Future<T> submit(final Callable<T> task) {
      return executor.submit(task);
    }

    List<Thread> threads() {
      return threads;
    }

    /**
     * Waits until every started caller is parked: one blocked on the token request, the others on
     * the lock.
     */
    void awaitAllWaiting() throws InterruptedException {
      final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (!allParked()) {
        assertThat(System.nanoTime()).as("callers did not park in time").isLessThan(deadline);
        TimeUnit.MILLISECONDS.sleep(5);
      }
    }

    private boolean allParked() {
      return threads.stream().allMatch(Callers::isParked);
    }

    /** Waiting on the lock, or inside the token request: the caller that sent the request. */
    private static boolean isParked(final Thread thread) {
      if (thread.getState() == Thread.State.WAITING
          || thread.getState() == Thread.State.TIMED_WAITING) {
        return true;
      }
      return thread.getState() == Thread.State.RUNNABLE
          && Arrays.stream(thread.getStackTrace())
              .anyMatch(frame -> frame.getClassName().equals(HTTPRequest.class.getName()));
    }

    void shutdownNow() {
      executor.shutdownNow();
    }
  }
}
