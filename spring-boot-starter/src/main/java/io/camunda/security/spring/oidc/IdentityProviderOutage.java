/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.io.IOException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

/**
 * Tells an outage of the identity provider from a failure that no retry removes. An outage is a
 * failed I/O exchange or an answer of the provider with a 5xx status. A client error status of the
 * discovery endpoint, a mismatch of the issuer, and a malformed value are configuration errors.
 */
final class IdentityProviderOutage {

  /** Enough of the chain to reach the I/O cause below a few wrappers, and still end on a cycle. */
  private static final int MAX_CAUSE_DEPTH = 10;

  private IdentityProviderOutage() {}

  /**
   * Whether the failure, or one of its causes, is an I/O failure or a server error of the provider.
   */
  static boolean isCausing(final Throwable failure) {
    var current = failure;
    for (var depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
      if (current instanceof IOException
          || current instanceof ResourceAccessException
          || current instanceof HttpServerErrorException) {
        return true;
      }
      current = current.getCause() == current ? null : current.getCause();
    }
    return false;
  }
}
