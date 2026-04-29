/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.config.headers;

import io.camunda.security.autoconfigure.spring.config.headers.values.CrossOriginOpenerPolicy;

/**
 * Configures Cross-Origin-Opener-Policy (COOP) header for window isolation.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">MDN:
 *     Cross-Origin-Opener-Policy</a>
 */
public class CrossOriginOpenerPolicyConfig {

  /** Default: SAME_ORIGIN_ALLOW_POPUPS. */
  private CrossOriginOpenerPolicy value = CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS;

  public CrossOriginOpenerPolicy getValue() {
    return value;
  }

  public void setValue(final CrossOriginOpenerPolicy value) {
    this.value = value;
  }
}
