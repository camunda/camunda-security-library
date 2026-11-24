/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Obtains an access token with the OAuth2 client credentials grant ({@code client_secret_post}) and
 * sends it as {@code Authorization: Bearer ...}.
 *
 * <p>The token is cached and refreshed shortly before it expires (30 seconds, or half the lifetime
 * of a short-lived token). One caller at a time makes a token request; the others wait, and then
 * use the token it cached. A response without {@code expires_in} is not cached. If a refresh fails,
 * the old token is used until it expires. After a {@code 401}, {@link #shouldRetryRequest} drops
 * the rejected token and fetches a new one. {@code shouldRetryRequest} may be called from any
 * thread; the provider never repeats a request itself.
 *
 * <p>{@link TokenRequestWorker} sets the timeouts of a token request, and {@link TokenResponses}
 * sets the rules for the response.
 */
public final class OidcClientCredentialsProvider implements OutboundCredentialsProvider {

  private static final Logger LOG = LoggerFactory.getLogger(OidcClientCredentialsProvider.class);

  private final OidcClientCredentialsConfiguration config;
  private final Clock clock;
  private final TokenRequestWorker worker;
  // Fair, so that new callers overtake queued waiters less often.
  private final ReentrantLock lock = new ReentrantLock(true);
  // Read without the lock, written only under it.
  private volatile CachedToken cached;
  // Guarded by the lock: true after a failed refresh that kept the old token, until a success.
  private boolean refreshFailing;

  public OidcClientCredentialsProvider(final OidcClientCredentialsConfiguration config) {
    this(config, Clock.systemUTC(), TokenRequestWorker::sendOverConnection);
  }

  OidcClientCredentialsProvider(
      final OidcClientCredentialsConfiguration config, final Clock clock) {
    this(config, clock, TokenRequestWorker::sendOverConnection);
  }

  OidcClientCredentialsProvider(
      final OidcClientCredentialsConfiguration config,
      final Clock clock,
      final TokenRequestWorker.TokenSender sender) {
    this.config = config;
    this.clock = clock;
    worker = new TokenRequestWorker(config, sender);
  }

  @Override
  public void applyCredentials(final CredentialsApplier applier) throws IOException {
    if (worker.isClosed()) {
      throw worker.noResponse("the provider is closed", null);
    }
    final CachedToken token = cached;
    applier.put("Authorization", (isUsable(token) ? token : refresh(null)).authorizationHeader());
  }

  /**
   * Compares the new token with the cached one, not with the token that the failed request carried.
   * A late {@code 401} for an old token after a refresh therefore drops the new token too.
   */
  @Override
  public boolean shouldRetryRequest(final StatusCode statusCode) {
    if (!statusCode.isUnauthorized() || worker.isClosed()) {
      return false;
    }
    final CachedToken seen = cached;
    if (seen == null) {
      // Cold start, a failed cold start, or a token that is not cached: the retry fetches a new
      // token anyway.
      return true;
    }
    try {
      // The same token again means the IdP does not help; a retry would be rejected again.
      return !seen.accessToken().equals(refresh(seen).accessToken());
    } catch (final TokenRequestException e) {
      if (Thread.currentThread().isInterrupted()) {
        LOG.debug(
            "Client '{}' was interrupted while waiting for a token; no retry", config.clientId());
      } else {
        // The message is sanitized and has no secret, so no stack trace is needed.
        LOG.warn(
            "Cannot retry after an unauthorized response: token request for client '{}' failed: {}",
            config.clientId(),
            e.getMessage());
      }
      return false;
    }
  }

  /**
   * Stops the worker thread and closes a running token request. Later calls fail, also with a
   * cached token.
   */
  @Override
  public void close() {
    worker.close();
  }

  /**
   * Under the lock: drops {@code rejected} if it is still cached, checks the cache again, and else
   * fetches a token. {@code rejected} is {@code null} unless a {@code 401} is being handled.
   */
  private CachedToken refresh(final CachedToken rejected) throws TokenRequestException {
    final long deadline = System.nanoTime() + config.requestTimeout().toNanos();
    acquireLock(deadline);
    try {
      CachedToken current = cached;
      if (rejected != null && current == rejected) {
        cached = null;
        current = null;
      }
      if (isUsable(current)) {
        return current;
      }
      return fetchOrKeepOld(current, rejected == null, deadline);
    } finally {
      lock.unlock();
    }
  }

  private void acquireLock(final long deadline) throws TokenRequestException {
    try {
      if (!lock.tryLock(TokenRequestWorker.remaining(deadline), TimeUnit.NANOSECONDS)) {
        throw new TokenRequestException(
            "Timed out after "
                + config.requestTimeout()
                + " waiting for a token request of client '"
                + config.clientId()
                + "'",
            TokenRequestException.NO_RESPONSE,
            null,
            null,
            null);
      }
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TokenRequestException(
          "Interrupted while waiting for an access token for client '" + config.clientId() + "'",
          TokenRequestException.NO_RESPONSE,
          null,
          null,
          e);
    }
  }

  /**
   * Must be called under the lock. If the request fails and {@code mayKeepOld} is set, the old
   * token is used until it expires. An interrupted caller always fails.
   */
  private CachedToken fetchOrKeepOld(
      final CachedToken old, final boolean mayKeepOld, final long deadline)
      throws TokenRequestException {
    try {
      final CachedToken token = fetchToken(deadline);
      cached = token.refreshAt() != null ? token : null;
      refreshFailing = false;
      return token;
    } catch (final TokenRequestException e) {
      // Without an old token, do not read the clock: it may be what failed. After close(), never
      // fall back to the old token.
      if (!mayKeepOld
          || old == null
          || worker.isClosed()
          || Thread.currentThread().isInterrupted()
          || !clock.instant().isBefore(old.expiresAt())) {
        throw e;
      }
      logKeptOldToken(old, e);
      return old;
    }
  }

  /** A WARN for the first failure in a row, DEBUG for the next ones, so an outage logs once. */
  private void logKeptOldToken(final CachedToken old, final TokenRequestException e) {
    final String message =
        "Token refresh for client '{}' failed; the old token is used until {}: {}";
    // The message is sanitized and has no secret, so no stack trace is needed.
    if (refreshFailing) {
      LOG.debug(message, config.clientId(), old.expiresAt(), e.getMessage());
    } else {
      refreshFailing = true;
      LOG.warn(message, config.clientId(), old.expiresAt(), e.getMessage());
    }
  }

  private boolean isUsable(final CachedToken token) {
    return token != null && clock.instant().isBefore(token.refreshAt());
  }

  /** Every failure, including transport errors and unexpected ones, is a TokenRequestException. */
  private CachedToken fetchToken(final long deadline) throws TokenRequestException {
    try {
      return requestToken(deadline);
    } catch (final TokenRequestException e) {
      throw e;
    } catch (final IOException | RuntimeException e) {
      throw new TokenRequestException(
          String.format(
              "Token request for client '%s' to %s failed: %s",
              config.clientId(), config.redactedTokenUri(), e.getClass().getSimpleName()),
          TokenRequestException.NO_RESPONSE,
          null,
          null,
          e);
    }
  }

  private CachedToken requestToken(final long deadline) throws IOException {
    LOG.debug(
        "Requesting access token for client '{}' from {}",
        config.clientId(),
        config.redactedTokenUri());
    final HTTPRequest request = TokenResponses.buildRequest(config);
    final Instant sentAt = clock.instant();
    final HTTPResponse response = worker.send(request, deadline);
    if (response.getStatusCode() != HTTPResponse.SC_OK) {
      throw TokenResponses.failure(response, config.clientId());
    }
    return TokenResponses.parseToken(response, sentAt, config.clientId());
  }
}
