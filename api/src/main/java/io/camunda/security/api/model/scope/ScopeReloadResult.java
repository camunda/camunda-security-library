/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.scope;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * The result of a runtime change to one scope.
 *
 * @param basePath the scope's normalized base path
 * @param outcome what the change did
 * @param generation the generation the scope serves after the change, {@code 0} when it serves none
 * @param duration how long the change took, including any identity-provider check
 * @param failure why the change was not applied, for {@link ScopeReloadOutcome#FAILED} and {@link
 *     ScopeReloadOutcome#KEPT_PREVIOUS}; otherwise {@code null}
 */
public record ScopeReloadResult(
    String basePath,
    ScopeReloadOutcome outcome,
    long generation,
    Duration duration,
    RuntimeException failure) {

  public ScopeReloadResult {
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(outcome, "outcome must not be null");
    Objects.requireNonNull(duration, "duration must not be null");
  }

  /** Whether the scope now serves what the change asked for. */
  public boolean applied() {
    return outcome.applied();
  }

  /** Whether the change ended the scope's existing sessions. */
  public boolean sessionsInvalidated() {
    return outcome == ScopeReloadOutcome.REPLACED || outcome == ScopeReloadOutcome.REMOVED;
  }

  public Optional<RuntimeException> failureCause() {
    return Optional.ofNullable(failure);
  }

  /**
   * Returns this result, or throws its failure when the change was not applied because of one.
   *
   * @throws RuntimeException the failure of a {@link ScopeReloadOutcome#FAILED} or {@link
   *     ScopeReloadOutcome#KEPT_PREVIOUS} result
   */
  public ScopeReloadResult orThrow() {
    if (failure != null) {
      throw failure;
    }
    return this;
  }
}
