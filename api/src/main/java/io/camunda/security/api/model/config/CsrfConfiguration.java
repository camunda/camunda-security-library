/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.HashSet;
import java.util.Set;

/** CSRF protection settings, bound to {@code camunda.security.csrf.*}. */
public class CsrfConfiguration {

  /** Default: true (enabled). */
  private boolean enabled = true;

  /**
   * When {@code false}, the {@code X-CSRF-TOKEN} cookie is set with {@code HttpOnly=false} so
   * browser-side JavaScript can read the token and echo it on subsequent requests. Default is
   * {@code false} because that is what every browser-facing webapp host needs; flip to {@code true}
   * for hosts that exclusively serve API clients reading the token from response headers.
   */
  private boolean cookieHttpOnly = false;

  /**
   * Path patterns CSRF protection ignores in addition to the always-ignored unprotected paths and
   * the logout endpoint. Use ant-style patterns. Hosts that need to exempt actuator endpoints (e.g.
   * {@code /actuator/loggers}) populate this set.
   *
   * <p>The login endpoint is deliberately not exemptable this way: it always requires a valid CSRF
   * token, even on a browser with no session yet, so that a cross-site {@code POST} cannot silently
   * replace an already-authenticated victim's session with an attacker-controlled one (see {@code
   * CsrfProtectionRequestMatcher} and camunda/security-testing-findings#281).
   */
  private Set<String> ignoredPathPatterns = new HashSet<>();

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isCookieHttpOnly() {
    return cookieHttpOnly;
  }

  public void setCookieHttpOnly(final boolean cookieHttpOnly) {
    this.cookieHttpOnly = cookieHttpOnly;
  }

  public Set<String> getIgnoredPathPatterns() {
    return ignoredPathPatterns;
  }

  public void setIgnoredPathPatterns(final Set<String> ignoredPathPatterns) {
    this.ignoredPathPatterns = ignoredPathPatterns;
  }
}
