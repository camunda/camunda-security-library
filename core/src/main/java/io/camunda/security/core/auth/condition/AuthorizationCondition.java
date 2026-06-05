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

/**
 * Describes how a {@link io.camunda.security.core.auth.SecurityContext} should evaluate
 * authorizations when securing a query. Implementations wrap a single {@link
 * io.camunda.security.core.auth.RequiredAuthorization} or compose multiple authorizations (for
 * example, disjunctive {@code anyOf} checks). Search backends inspect the concrete condition type
 * to translate it into backend-specific predicates while callers express their intent
 * declaratively.
 *
 * <p>This interface is sealed: the only permitted implementations are {@link
 * SingleAuthorizationCondition} and {@link AnyOfAuthorizationCondition}.
 */
public sealed interface AuthorizationCondition
    permits SingleAuthorizationCondition, AnyOfAuthorizationCondition {

  /** Returns the underlying authorizations (single returns a size-1 list). */
  default List<RequiredAuthorization<?>> authorizations() {
    if (this instanceof SingleAuthorizationCondition(RequiredAuthorization<?> authorization)) {
      return List.of(authorization);
    }
    if (this instanceof AnyOfAuthorizationCondition(List<RequiredAuthorization<?>> children)) {
      return children;
    }
    throw new IllegalStateException("Unknown AuthorizationCondition type: " + getClass());
  }
}
