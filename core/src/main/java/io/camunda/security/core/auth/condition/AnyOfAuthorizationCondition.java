/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth.condition;

import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import java.util.Objects;

/**
 * Disjunctive {@link AuthorizationCondition} that grants access when any child authorization is
 * satisfied.
 */
public record AnyOfAuthorizationCondition(List<RequiredAuthorization<?>> authorizations)
    implements AuthorizationCondition {

  /**
   * @throws IllegalArgumentException when {@code authorizations} is {@code null}, empty, or
   *     contains a {@code null} element
   */
  public AnyOfAuthorizationCondition {
    if (authorizations == null || authorizations.isEmpty()) {
      throw new IllegalArgumentException(
          "AnyOfAuthorizationCondition requires at least one authorization");
    }
    if (authorizations.stream().anyMatch(Objects::isNull)) {
      throw new IllegalArgumentException(
          "AnyOfAuthorizationCondition requires non-null authorizations");
    }
    authorizations = List.copyOf(authorizations);
  }

  public <T> List<RequiredAuthorization<?>> applicableAuthorizations(final T document) {
    return authorizations().stream()
        .filter(
            auth -> {
              try {
                @SuppressWarnings("unchecked")
                final RequiredAuthorization<T> typedAuth = (RequiredAuthorization<T>) auth;
                return typedAuth.appliesTo(document);
              } catch (final ClassCastException e) {
                return false;
              }
            })
        .toList();
  }
}
