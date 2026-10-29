/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.scope;

import java.util.List;
import java.util.Optional;

/** The per-scope results of reloading every scope from the scope providers. */
public record ScopeReloadReport(List<ScopeReloadResult> results) {

  public ScopeReloadReport {
    results = List.copyOf(results);
  }

  /** The scopes whose change was not applied because of a failure. */
  public List<ScopeReloadResult> failures() {
    return results.stream().filter(result -> result.failure() != null).toList();
  }

  public Optional<ScopeReloadResult> result(final String basePath) {
    return results.stream().filter(result -> result.basePath().equals(basePath)).findFirst();
  }
}
