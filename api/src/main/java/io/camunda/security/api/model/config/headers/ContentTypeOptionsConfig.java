/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

/**
 * Configures X-Content-Type-Options header to prevent MIME type sniffing attacks.
 *
 * <p>The X-Content-Type-Options header prevents browsers from MIME-sniffing a response away from
 * the declared Content-Type. When enabled (default state), it sets the header value to 'nosniff',
 * which instructs browsers to strictly follow the Content-Type header provided by the server.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options">MDN:
 *     X-Content-Type-Options</a>
 */
public class ContentTypeOptionsConfig {

  /**
   * Controls whether the X-Content-Type-Options: nosniff header is sent.
   *
   * <p>Default: true (enabled).
   */
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
