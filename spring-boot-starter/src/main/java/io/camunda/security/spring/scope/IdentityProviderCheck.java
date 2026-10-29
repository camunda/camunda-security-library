/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Checks, before a generation goes live, that every identity provider it configures can be
 * resolved. Resolving fetches the discovery document of each provider configured by its issuer; the
 * registrations stay resolved in the generation, so its first requests need no discovery of their
 * own.
 */
final class IdentityProviderCheck {

  private IdentityProviderCheck() {}

  /**
   * {@code null} when every provider of the generation resolved, otherwise an exception that names
   * each provider that did not and carries the first failure as its cause.
   */
  static IllegalStateException unreachable(final ScopeGeneration generation) {
    final Map<String, RuntimeException> failures = new LinkedHashMap<>();
    for (final var clients : generation.oidcClients()) {
      clients.resolveAll().forEach(failures::putIfAbsent);
    }
    if (failures.isEmpty()) {
      return null;
    }
    final var first = failures.values().iterator().next();
    return new IllegalStateException(
        "OIDC provider(s) "
            + failures.keySet()
            + " of generation "
            + generation.number()
            + " could not be resolved: "
            + first.getMessage(),
        first);
  }
}
