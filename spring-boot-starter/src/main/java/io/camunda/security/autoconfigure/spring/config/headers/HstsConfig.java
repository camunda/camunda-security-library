/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.config.headers;

/**
 * Configures HTTP Strict Transport Security (HSTS) to enforce HTTPS connections.
 *
 * <p>Per RFC 6797 the header is only sent over HTTPS connections.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security">MDN:
 *     Strict-Transport-Security</a>
 */
public class HstsConfig {

  /** Default max-age of 1 year (in seconds). */
  private static final long DEFAULT_MAX_AGE_IN_SECONDS = 60 * 60 * 24 * 365;

  /** Default: true (enabled). */
  private boolean enabled = true;

  /** Default: 31536000 (1 year). */
  private long maxAgeInSeconds = DEFAULT_MAX_AGE_IN_SECONDS;

  /** Default: false. WARNING: applies to ALL subdomains. */
  private boolean includeSubDomains = false;

  /** Default: false. WARNING: preload list inclusion is practically permanent. */
  private boolean preload = false;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isDisabled() {
    return !enabled;
  }

  public long getMaxAgeInSeconds() {
    return maxAgeInSeconds;
  }

  public void setMaxAgeInSeconds(final long maxAgeInSeconds) {
    this.maxAgeInSeconds = maxAgeInSeconds;
  }

  public boolean isIncludeSubDomains() {
    return includeSubDomains;
  }

  public void setIncludeSubDomains(final boolean includeSubDomains) {
    this.includeSubDomains = includeSubDomains;
  }

  public boolean isPreload() {
    return preload;
  }

  public void setPreload(final boolean preload) {
    this.preload = preload;
  }
}
