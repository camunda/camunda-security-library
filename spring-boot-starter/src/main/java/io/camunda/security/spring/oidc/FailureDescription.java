/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.util.StringUtils;

/**
 * A safe, specific description of a failure in an exchange with an identity provider, for a log
 * line: the exception chain's simple names, plus the OAuth2 error code or CSL's own message where
 * those are known not to carry secrets.
 *
 * <p>Specificity is the point. A timeout, a refused connection, a TLS failure and a rejected client
 * assertion all surface as the same {@code ResourceAccessException} or {@code
 * IllegalStateException}, and an operator cannot act on that. What stays out is the exception
 * <em>message</em> of anything the HTTP stack or the IdP produced: {@code ResourceAccessException}
 * embeds the request URI, and Spring strips its query string but not its user-info; Spring's token
 * response client builds {@code invalid_token_response} descriptions from that message; and an IdP
 * may echo request parameters into {@code error_description}.
 *
 * <p>Shared by {@code RefreshTokenRevocationLogoutHandler} and {@code OAuth2RefreshTokenFilter}, so
 * the two places that report a failed exchange with the token or revocation endpoint apply one
 * policy.
 */
public final class FailureDescription {

  /** Enough of the chain to name a root cause without turning a log line into a stack trace. */
  private static final int MAX_CAUSE_DEPTH = 4;

  private FailureDescription() {}

  /**
   * Describes the failure without any message the library has not vetted.
   *
   * @param throwable the failure, possibly with causes
   * @return for example {@code ClientAuthorizationException: invalid_token_response <-
   *     ResourceAccessException <- ConnectException}
   */
  public static String describe(final Throwable throwable) {
    final var description = new StringBuilder();
    var current = throwable;
    var seen = 0;
    while (current != null && seen < MAX_CAUSE_DEPTH) {
      if (seen > 0) {
        description.append(" <- ");
      }
      description.append(current.getClass().getSimpleName());
      if (current instanceof final OAuth2AuthorizationException oauth
          && StringUtils.hasText(oauth.getError().getErrorCode())) {
        description.append(": ").append(oauth.getError().getErrorCode());
      } else if (isThrownByCamunda(current) && StringUtils.hasText(current.getMessage())) {
        // CSL's own messages name a registration, a keystore path or a configuration property.
        description.append(": ").append(current.getMessage());
      }
      current = current.getCause() == current ? null : current.getCause();
      seen++;
    }
    return description.toString();
  }

  /**
   * Whether {@link AssertionJwkProvider} raised this, judged by the frame that threw.
   *
   * <p>Deliberately one class rather than the {@code io.camunda.security} package. This decides
   * what reaches a log, so it is an allowlist of messages someone has actually read: that class
   * names a registrationId, a configuration property or a keystore path, and nothing else. Widen it
   * only by reading the candidate's messages first.
   */
  private static boolean isThrownByCamunda(final Throwable throwable) {
    final var frames = throwable.getStackTrace();
    return frames.length > 0
        && frames[0].getClassName().startsWith(AssertionJwkProvider.class.getName());
  }
}
