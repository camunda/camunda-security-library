/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import java.io.IOException;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Obtains an access token with the OAuth2 client credentials grant ({@code client_secret_post}) and
 * sends it as {@code Authorization: Bearer ...}.
 *
 * <p>The token is cached and refreshed shortly before it expires (30 seconds, or half the lifetime
 * of a short-lived token). Concurrent callers share one token request, and its outcome. A response
 * without {@code expires_in} is not cached, but callers that waited for that request still share
 * it. After a {@code 401}, {@link #shouldRetryRequest} fetches a new token, blocking on at most one
 * token request, and answers {@code true} only if it differs from the cached one. If that request
 * fails, the rejected token is dropped: the next call asks the IdP again, as on a cold start,
 * instead of sending the rejected token. If a refresh fails without a {@code 401}, the old token is
 * used until it expires. {@code shouldRetryRequest} may be called from any thread; the provider
 * never repeats a request itself.
 *
 * <p>A token request that gets no answer ends at the read timeout. An interrupt does not stop it,
 * but it does stop a caller that waits for the lock. The response must be strict: {@code
 * Content-Type: application/json}, a non-blank {@code access_token} and {@code token_type} ({@code
 * Bearer} or {@code DPoP}), and a numeric {@code expires_in} if present.
 */
public final class OidcClientCredentialsProvider implements OutboundCredentialsProvider {

  private static final Logger LOG = LoggerFactory.getLogger(OidcClientCredentialsProvider.class);
  private static final Duration REFRESH_SKEW = Duration.ofSeconds(30);
  private static final int MAX_DESCRIPTION_LENGTH = 200;

  private final OidcClientCredentialsConfiguration config;
  private final Clock clock;
  // Fair, so that new callers overtake queued waiters less often.
  private final ReentrantLock lock = new ReentrantLock(true);
  // The only mutable field: read once per call without the lock, replaced as a whole under it.
  private volatile State state = State.EMPTY;

  public OidcClientCredentialsProvider(final OidcClientCredentialsConfiguration config) {
    this(config, Clock.systemUTC());
  }

  OidcClientCredentialsProvider(
      final OidcClientCredentialsConfiguration config, final Clock clock) {
    this.config = config;
    this.clock = clock;
  }

  @Override
  public void applyCredentials(final CredentialsApplier applier) throws IOException {
    final State seen = state;
    final CachedToken token = isUsable(seen.cached()) ? seen.cached() : refreshOrKeepOld(seen);
    applier.put("Authorization", token.authorizationHeader());
  }

  /**
   * If the refresh fails, the old token is used until it expires. It is read from {@link #state}
   * again, so a token that was dropped after a {@code 401} is never used. An interrupted caller
   * always fails.
   */
  private CachedToken refreshOrKeepOld(final State seen) throws TokenRequestException {
    try {
      return refresh(seen, false);
    } catch (final TokenRequestException e) {
      final CachedToken old = state.cached();
      if (!Thread.currentThread().isInterrupted()
          && old != null
          && clock.instant().isBefore(old.expiresAt())) {
        LOG.debug(
            "Refresh for client '{}' failed; the old token is used until it expires",
            config.clientId());
        return old;
      }
      throw e;
    }
  }

  /**
   * Compares the new token with the cached one, not with the token that the failed request carried.
   * After the first {@code 401}, a late {@code 401} for the same old token can fetch one more
   * token, or drop a new token when the IdP is down.
   */
  @Override
  public boolean shouldRetryRequest(final StatusCode statusCode) {
    if (!statusCode.isUnauthorized()) {
      return false;
    }
    final State seen = state;
    if (seen.cached() == null) {
      // Nothing is cached, so the retry fetches a new token anyway.
      return true;
    }
    try {
      final CachedToken fresh = refresh(seen, true);
      // The same token again means the IdP does not help; a retry would be rejected again.
      return !seen.cached().accessToken().equals(fresh.accessToken());
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
   * Fetches a token, unless another caller made a token request after {@code seen} was read: then
   * that outcome is shared, so callers waiting on a failing or hanging IdP fail together after one
   * request instead of one timeout each.
   *
   * <p>If {@code dropRejected} is set, the caller got a {@code 401} for {@code seen.cached()}. When
   * the request then fails, that token is dropped, so the next call asks the IdP again, as on a
   * cold start, instead of sending the rejected token. During an IdP outage after a {@code 401},
   * every call then tries the IdP, one shared request at a time. Otherwise a failed refresh keeps
   * the old token, and {@code applyCredentials} uses it until it expires.
   */
  private CachedToken refresh(final State seen, final boolean dropRejected)
      throws TokenRequestException {
    try {
      lock.lockInterruptibly();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TokenRequestException(
          "Interrupted while waiting for an access token for client '" + config.clientId() + "'",
          TokenRequestException.NO_RESPONSE,
          null,
          null,
          e);
    }
    try {
      final State now = state;
      if (now.attempt() > seen.attempt()) {
        if (now.lastFailure() != null) {
          if (dropRejected && now.cached() == seen.cached()) {
            state = new State(null, now.attempt(), now.lastToken(), now.lastFailure());
          }
          throw now.lastFailure().forWaiter(config.clientId());
        }
        if (now.lastToken() != null) {
          return now.lastToken();
        }
      }
      return fetchAndPublish(now, seen, dropRejected);
    } finally {
      lock.unlock();
    }
  }

  /** Must be called under the lock; replaces {@link #state} once, on success and on failure. */
  private CachedToken fetchAndPublish(final State now, final State seen, final boolean dropRejected)
      throws TokenRequestException {
    try {
      final CachedToken token = fetchToken();
      final CachedToken cacheable = token.refreshAt() != null ? token : null;
      // An uncacheable token is not cached, but callers that waited for this request share it.
      state = new State(cacheable, now.attempt() + 1, token, null);
      return token;
    } catch (final TokenRequestException e) {
      // Keep the old token: applyCredentials uses it until it expires. Drop it only if the IdP
      // rejected it with a 401.
      final CachedToken keep = dropRejected && now.cached() == seen.cached() ? null : now.cached();
      state = new State(keep, now.attempt() + 1, null, e);
      throw e;
    }
  }

  private boolean isUsable(final CachedToken token) {
    return token != null && clock.instant().isBefore(token.refreshAt());
  }

  /** Every failure, including transport errors and unexpected ones, is a TokenRequestException. */
  private CachedToken fetchToken() throws TokenRequestException {
    try {
      return requestToken();
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

  private CachedToken requestToken() throws IOException {
    LOG.debug(
        "Requesting access token for client '{}' from {}",
        config.clientId(),
        config.redactedTokenUri());
    final HTTPRequest request = buildRequest();
    final Instant sentAt = clock.instant();
    final HTTPResponse response = request.send();
    if (response.getStatusCode() != HTTPResponse.SC_OK) {
      throw failure(response);
    }
    return parseToken(response, sentAt);
  }

  private HTTPRequest buildRequest() {
    final TokenRequest.Builder builder =
        new TokenRequest.Builder(
            config.tokenUri(),
            new ClientSecretPost(
                new ClientID(config.clientId()), new Secret(config.clientSecret())),
            new ClientCredentialsGrant());
    if (!config.scopes().isEmpty()) {
      builder.scope(new Scope(config.scopes().toArray(new String[0])));
    }
    // Custom parameters, not resources(URI): some IdPs take values that are not URIs.
    putIfPresent(builder, "audience", config.audience());
    putIfPresent(builder, "resource", config.resource());
    final HTTPRequest request = builder.build().toHTTPRequest();
    request.setAccept("application/json");
    request.setConnectTimeout(toMillis(config.connectTimeout()));
    request.setReadTimeout(toMillis(config.readTimeout()));
    request.setFollowRedirects(false);
    return request;
  }

  private static void putIfPresent(
      final TokenRequest.Builder builder, final String name, final String value) {
    if (!ConfigurationChecks.isBlank(value)) {
      builder.customParameter(name, value);
    }
  }

  /** At least 1 ms, because {@code HttpURLConnection} reads 0 as "wait forever". */
  private static int toMillis(final Duration timeout) {
    return (int) Math.max(1L, (timeout.toNanos() + 999_999L) / 1_000_000L);
  }

  private CachedToken parseToken(final HTTPResponse response, final Instant sentAt)
      throws TokenRequestException {
    final AccessToken token;
    try {
      token = TokenResponse.parse(response).toSuccessResponse().getTokens().getAccessToken();
    } catch (final ParseException e) {
      // No cause: the Nimbus exception can quote the response body, and so the token.
      throw unusableResponse(e, response.getStatusCode());
    }
    if (AccessTokenType.N_A.equals(token.getType())) {
      throw new TokenRequestException(
          "Token response of client '" + config.clientId() + "' is not usable: token_type N_A",
          response.getStatusCode(),
          null,
          null,
          null);
    }
    if (!isVisibleAscii(token.getValue())) {
      throw new TokenRequestException(
          "Token response of client '"
              + config.clientId()
              + "' is not usable: access_token has characters that are not allowed in a header",
          response.getStatusCode(),
          null,
          null,
          null);
    }
    final String header = token.toAuthorizationHeader();
    final long lifetimeSeconds = token.getLifetime();
    if (lifetimeSeconds <= 0) {
      LOG.debug(
          "Token response of client '{}' has no expires_in; the token is not cached",
          config.clientId());
      return new CachedToken(header, token.getValue(), null, null);
    }
    final Duration lifetime = Duration.ofSeconds(lifetimeSeconds);
    final Duration skew =
        REFRESH_SKEW.compareTo(lifetime.dividedBy(2)) < 0 ? REFRESH_SKEW : lifetime.dividedBy(2);
    try {
      return new CachedToken(
          header, token.getValue(), sentAt.plus(lifetime).minus(skew), sentAt.plus(lifetime));
    } catch (final DateTimeException | ArithmeticException e) {
      LOG.debug(
          "expires_in in the token response of client '{}' is out of range; the token is not cached",
          config.clientId());
      return new CachedToken(header, token.getValue(), null, null);
    }
  }

  private static boolean isVisibleAscii(final String value) {
    return value.chars().allMatch(c -> c >= 0x21 && c <= 0x7E);
  }

  private TokenRequestException unusableResponse(final ParseException e, final int status) {
    return new TokenRequestException(
        "Token response of client '" + config.clientId() + "' is not usable: " + describe(e),
        status,
        null,
        null,
        null);
  }

  /**
   * Nimbus names the field that is wrong, not its value. A message that repeats the message of its
   * cause is withheld: the JSON parser quotes the input there, and so maybe the token.
   */
  static String describe(final ParseException e) {
    final String message = e.getMessage();
    final Throwable cause = e.getCause();
    if (message == null
        || cause != null && cause.getMessage() != null && message.contains(cause.getMessage())) {
      return "the response cannot be parsed";
    }
    return sanitize(truncate(message));
  }

  private TokenRequestException failure(final HTTPResponse response) {
    final int status = response.getStatusCode();
    String error = null;
    String description = null;
    try {
      final TokenErrorResponse parsed = TokenErrorResponse.parse(response);
      error = sanitize(parsed.getErrorObject().getCode());
      description = sanitize(truncate(parsed.getErrorObject().getDescription()));
    } catch (final ParseException | RuntimeException e) {
      LOG.debug(
          "Cannot parse the error response of the token request of client '{}' (HTTP {})",
          config.clientId(),
          status);
    }
    LOG.debug(
        "Token request for client '{}' failed with HTTP {} (error={})",
        config.clientId(),
        status,
        error);
    return new TokenRequestException(
        String.format(
            "Token request for client '%s' failed with HTTP %d (error=%s, error_description=%s)",
            config.clientId(), status, error, description),
        status,
        error,
        description,
        null);
  }

  /** Replaces line breaks and other control characters, so a response cannot forge log lines. */
  private static String sanitize(final String value) {
    if (value == null) {
      return null;
    }
    final StringBuilder clean = new StringBuilder(value.length());
    value
        .codePoints()
        .forEach(
            c ->
                clean.appendCodePoint(
                    Character.isISOControl(c) || c == 0x2028 || c == 0x2029 ? '?' : c));
    return clean.toString();
  }

  private static String truncate(final String value) {
    if (value == null || value.length() <= MAX_DESCRIPTION_LENGTH) {
      return value;
    }
    return value.substring(0, MAX_DESCRIPTION_LENGTH);
  }

  /**
   * {@code refreshAt} is when the token stops being used: shortly before it expires, at most 30
   * seconds and at most half its lifetime early. It is {@code null} for a token that must not be
   * cached. {@code expiresAt} is when the token expires; it is {@code null} together with {@code
   * refreshAt}.
   */
  private static final class CachedToken {
    private final String authorizationHeader;
    private final String accessToken;
    private final Instant refreshAt;
    private final Instant expiresAt;

    CachedToken(
        final String authorizationHeader,
        final String accessToken,
        final Instant refreshAt,
        final Instant expiresAt) {
      this.authorizationHeader = authorizationHeader;
      this.accessToken = accessToken;
      this.refreshAt = refreshAt;
      this.expiresAt = expiresAt;
    }

    String authorizationHeader() {
      return authorizationHeader;
    }

    String accessToken() {
      return accessToken;
    }

    Instant refreshAt() {
      return refreshAt;
    }

    Instant expiresAt() {
      return expiresAt;
    }
  }

  /**
   * What callers read without the lock. {@code cached} is the token to use, {@code attempt} counts
   * token requests, and {@code lastToken} / {@code lastFailure} are the outcome of the latest one,
   * shared with callers that waited for it.
   */
  private static final class State {
    static final State EMPTY = new State(null, 0, null, null);

    private final CachedToken cached;
    private final long attempt;
    private final CachedToken lastToken;
    private final TokenRequestException lastFailure;

    State(
        final CachedToken cached,
        final long attempt,
        final CachedToken lastToken,
        final TokenRequestException lastFailure) {
      this.cached = cached;
      this.attempt = attempt;
      this.lastToken = lastToken;
      this.lastFailure = lastFailure;
    }

    CachedToken cached() {
      return cached;
    }

    long attempt() {
      return attempt;
    }

    CachedToken lastToken() {
      return lastToken;
    }

    TokenRequestException lastFailure() {
      return lastFailure;
    }
  }
}
