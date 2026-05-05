/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

/**
 * Configures cache control headers to prevent sensitive content from being cached.
 *
 * <p>When enabled (default), Spring Security sends Cache-Control: no-cache, no-store, max-age=0,
 * must-revalidate; Pragma: no-cache; Expires: 0.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control">MDN:
 *     Cache-Control</a>
 */
public class CacheControlConfig {

  /** Default: true (enabled). */
  private boolean enabled = true;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isDisabled() {
    return !enabled;
  }
}
