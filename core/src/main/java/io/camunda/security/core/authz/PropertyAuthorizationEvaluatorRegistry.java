/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Holds {@link PropertyAuthorizationEvaluator} instances keyed by their {@link
 * PropertyAuthorizationEvaluator#propertyName() propertyName} and routes evaluation requests to the
 * correct evaluator.
 *
 * <p>The {@link #findEvaluator} method performs an unchecked cast from the wildcard type to the
 * caller-specified {@code T}. Safety is contractual: callers must ensure the resource type matches
 * the evaluator's type parameter. Duplicate property names are rejected at construction time.
 */
public final class PropertyAuthorizationEvaluatorRegistry {

  private final Map<String, PropertyAuthorizationEvaluator<?>> evaluators;

  public PropertyAuthorizationEvaluatorRegistry(
      final List<PropertyAuthorizationEvaluator<?>> evaluators) {
    this.evaluators =
        evaluators.stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    PropertyAuthorizationEvaluator::propertyName,
                    Function.identity(),
                    (a, b) -> {
                      throw new IllegalStateException(
                          "Duplicate PropertyAuthorizationEvaluator for property name: "
                              + a.propertyName());
                    }));
  }

  /**
   * Returns the evaluator for {@code propertyName}, cast to the expected resource type {@code T}.
   * Returns {@link Optional#empty()} when no evaluator is registered for that property name.
   */
  @SuppressWarnings("unchecked")
  public <T> Optional<PropertyAuthorizationEvaluator<T>> findEvaluator(final String propertyName) {
    return Optional.ofNullable((PropertyAuthorizationEvaluator<T>) evaluators.get(propertyName));
  }
}
