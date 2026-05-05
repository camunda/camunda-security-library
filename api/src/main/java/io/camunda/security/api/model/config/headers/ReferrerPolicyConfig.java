/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

import io.camunda.security.api.model.config.headers.values.ReferrerPolicy;

/**
 * Configures Referrer-Policy header to control referrer information leakage.
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy">MDN:
 *     Referrer-Policy</a>
 */
public class ReferrerPolicyConfig {

  /** Default: STRICT_ORIGIN_WHEN_CROSS_ORIGIN. */
  private ReferrerPolicy value = ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN;

  public ReferrerPolicy getValue() {
    return value;
  }

  public void setValue(final ReferrerPolicy value) {
    this.value = value;
  }
}
