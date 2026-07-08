/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import io.camunda.security.spring.filter.JwtCookieAuthenticationFilter;
import java.util.Map;
import org.springframework.security.core.AuthenticationException;

/**
 * Issues and validates the short-lived JWT stored in the authentication cookie. Hosts implement
 * this SPI once per deployment mode; there is no library-supplied default.
 *
 * <p>The SPI boundary is at "validated claims". Resolving group, role, and tenant memberships from
 * those claims is the responsibility of the filter via {@code LazyTokenClaimsConverter} and {@code
 * MembershipPort} — this service must not attempt membership resolution.
 */
public interface JwtCookieTokenPort {

  /**
   * Optionally override this method if you want to use a different cookie name than the default
   * {@link JwtCookieAuthenticationFilter.DEFAULT_COOKIE_NAME}
   *
   * @return The name of the cookie to read the JWT from.
   */
  default String getCookieName() {
    return JwtCookieAuthenticationFilter.DEFAULT_COOKIE_NAME;
  }

  /**
   * Issues a signed JWT to be stored in the authentication cookie for the given user.
   *
   * @param userId the authenticated user's identifier
   * @return a signed JWT string suitable for storage in the auth cookie
   */
  String issue(String userId);

  /**
   * Validates the signed cookie JWT (signature, expiry, and any IdP-specific claims) and returns
   * the decoded claims map.
   *
   * <p>This method is responsible only for what this SPI uniquely knows — IdP-specific signature
   * verification. It must not resolve group, role, or tenant memberships; that resolution is
   * performed lazily by the filter via {@code LazyTokenClaimsConverter} and {@code MembershipPort}.
   *
   * @param cookieToken the raw JWT string extracted from the auth cookie
   * @return the decoded claims from the validated token
   * @throws AuthenticationException when the JWT is invalid or expired
   */
  Map<String, Object> validate(String cookieToken) throws AuthenticationException;
}
