/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.config.headers;

import io.camunda.security.autoconfigure.spring.config.headers.values.CrossOriginEmbedderPolicy;

/**
 * Configures Cross-Origin-Embedder-Policy (COEP) header for cross-origin isolation.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">MDN:
 *     Cross-Origin-Embedder-Policy</a>
 */
public class CrossOriginEmbedderPolicyConfig {

  /** Default: UNSAFE_NONE. */
  private CrossOriginEmbedderPolicy value = CrossOriginEmbedderPolicy.UNSAFE_NONE;

  public CrossOriginEmbedderPolicy getValue() {
    return value;
  }

  public void setValue(final CrossOriginEmbedderPolicy value) {
    this.value = value;
  }
}
