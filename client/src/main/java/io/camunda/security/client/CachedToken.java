/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@code refreshAt} is when the token stops being used: shortly before it expires, at most 30
 * seconds and at most half its lifetime early. It is {@code null} for a token that must not be
 * cached. {@code expiresAt} is when the token expires; it is {@code null} together with {@code
 * refreshAt}.
 */
final class CachedToken {

  private static final Logger LOG = LoggerFactory.getLogger(CachedToken.class);
  private static final Duration REFRESH_SKEW = Duration.ofSeconds(30);

  private final String authorizationHeader;
  private final String accessToken;
  private final Instant refreshAt;
  private final Instant expiresAt;

  private CachedToken(
      final String authorizationHeader,
      final String accessToken,
      final Instant refreshAt,
      final Instant expiresAt) {
    this.authorizationHeader = authorizationHeader;
    this.accessToken = accessToken;
    this.refreshAt = refreshAt;
    this.expiresAt = expiresAt;
  }

  /**
   * Creates the token of a response that was sent at {@code sentAt}. A lifetime that is not
   * positive, or that is out of range, gives a token that is not cached.
   */
  static CachedToken of(
      final String authorizationHeader,
      final String accessToken,
      final Instant sentAt,
      final long lifetimeSeconds,
      final String clientId) {
    if (lifetimeSeconds <= 0) {
      LOG.debug(
          "Token response of client '{}' has no expires_in; the token is not cached", clientId);
      return new CachedToken(authorizationHeader, accessToken, null, null);
    }
    final Duration lifetime = Duration.ofSeconds(lifetimeSeconds);
    final Duration skew =
        REFRESH_SKEW.compareTo(lifetime.dividedBy(2)) < 0 ? REFRESH_SKEW : lifetime.dividedBy(2);
    try {
      return new CachedToken(
          authorizationHeader,
          accessToken,
          sentAt.plus(lifetime).minus(skew),
          sentAt.plus(lifetime));
    } catch (final DateTimeException | ArithmeticException e) {
      LOG.debug(
          "expires_in in the token response of client '{}' is out of range; the token is not cached",
          clientId);
      return new CachedToken(authorizationHeader, accessToken, null, null);
    }
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
