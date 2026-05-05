/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

/**
 * Configures Permissions-Policy header to control browser feature access.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy">MDN:
 *     Permissions-Policy</a>
 */
public class PermissionsPolicyConfig {

  public static final String DEFAULT_PERMISSIONS_POLICY_VALUE =
      "accelerometer=(), "
          + "ambient-light-sensor=(), "
          + "attribution-reporting=(), "
          + "autoplay=(), "
          + "bluetooth=(), "
          + "browsing-topics=(), "
          + "camera=(), "
          + "compute-pressure=(), "
          + "cross-origin-isolated=(), "
          + "deferred-fetch=(), "
          + "deferred-fetch-minimal=(), "
          + "display-capture=(), "
          + "encrypted-media=(), "
          + "fullscreen=(self), "
          + "gamepad=(), "
          + "geolocation=(), "
          + "gyroscope=(), "
          + "hid=(), "
          + "identity-credentials-get=(), "
          + "idle-detection=(), "
          + "language-detector=(), "
          + "local-fonts=(), "
          + "magnetometer=(), "
          + "microphone=(), "
          + "midi=(), "
          + "otp-credentials=(), "
          + "payment=(), "
          + "picture-in-picture=(), "
          + "publickey-credentials-create=(), "
          + "publickey-credentials-get=(), "
          + "screen-wake-lock=(), "
          + "serial=(), "
          + "speaker-selection=(), "
          + "storage-access=(), "
          + "summarizer=(), "
          + "translator=(), "
          + "usb=(), "
          + "web-share=(), "
          + "window-management=(), "
          + "xr-spatial-tracking=()";

  private String value = DEFAULT_PERMISSIONS_POLICY_VALUE;

  public String getValue() {
    return value;
  }

  public void setValue(final String value) {
    this.value = value;
  }
}
