/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

import io.camunda.security.api.model.config.headers.values.FrameOptionMode;

/**
 * Configures X-Frame-Options header to prevent clickjacking attacks.
 *
 * <p>Modern applications should also use Content-Security-Policy frame-ancestors directive which
 * provides more granular control and supersedes X-Frame-Options in supporting browsers.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options">MDN:
 *     X-Frame-Options</a>
 */
public class FrameOptionsConfig {
  /** Default: true (enabled). */
  private boolean enabled = true;

  /** Default: SAMEORIGIN. */
  private FrameOptionMode mode = FrameOptionMode.SAMEORIGIN;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public boolean disabled() {
    return !enabled;
  }

  public FrameOptionMode getMode() {
    return mode;
  }

  public void setMode(final FrameOptionMode mode) {
    this.mode = mode;
  }
}
