/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Accumulates authorization check results and produces a single aggregated outcome.
 *
 * <p>Usage:
 *
 * <pre>{@code
 * var agg = new RejectionAggregator();
 * agg.add(checkPort.check(auth, req1));
 * agg.add(checkPort.check(auth, req2));
 * Either<List<AuthorizationRejection>, Void> result = agg.build();
 * }</pre>
 */
public final class RejectionAggregator {

  private final List<AuthorizationRejection> rejections = new ArrayList<>();

  public RejectionAggregator add(final Either<AuthorizationRejection, Void> result) {
    Objects.requireNonNull(result, "result");
    if (result.isLeft()) {
      final var rejection = Objects.requireNonNull(result.leftValue(), "rejection");
      rejections.add(rejection);
    }
    return this;
  }

  /**
   * Returns {@code Either.right(null)} when no rejections were added, or {@code
   * Either.left(rejections)} with an immutable copy of all accumulated rejections. {@code null} is
   * the canonical value for the {@code Void} right type.
   */
  public Either<List<AuthorizationRejection>, Void> build() {
    return rejections.isEmpty() ? Either.right(null) : Either.left(List.copyOf(rejections));
  }
}
