/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.config.headers;

import io.camunda.security.autoconfigure.spring.config.headers.values.CrossOriginResourcePolicy;

/**
 * Configures Cross-Origin-Resource-Policy (CORP) header for resource isolation.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Cross-Origin_Resource_Policy">MDN:
 *     Cross-Origin Resource Policy</a>
 */
public class CrossOriginResourcePolicyConfig {

  /** Default: SAME_SITE. */
  private CrossOriginResourcePolicy value = CrossOriginResourcePolicy.SAME_SITE;

  public CrossOriginResourcePolicy getValue() {
    return value;
  }

  public void setValue(final CrossOriginResourcePolicy value) {
    this.value = value;
  }
}
