/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Map;

/**
 * Inbound port for authorization checks. Returns {@link Either#right(Object) Either.right(null)}
 * when the principal is authorized, or {@link Either#left(Object) Either.left(rejection)} when
 * access is denied.
 *
 * <p>Inc 1 initial surface — batch-check methods deferred to Inc 2+.
 */
public interface AuthorizationCheckPort {

  <T> Either<AuthorizationRejection, Void> check(
      CamundaAuthentication authentication, RequiredAuthorization<T> authorization);

  /**
   * Claims-map variant. Converts {@code claims} to a {@link CamundaAuthentication} internally
   * before delegating to {@link #check(CamundaAuthentication, RequiredAuthorization)}.
   *
   * <p>Callers must ensure the map contains at least one principal claim (as configured by the
   * implementation). Otherwise implementations may throw {@link IllegalArgumentException}.
   *
   * <p>The default implementation throws {@link UnsupportedOperationException}. Implementations
   * that support this method should override it.
   */
  default <T> Either<AuthorizationRejection, Void> check(
      Map<String, Object> claims, RequiredAuthorization<T> authorization) {
    throw new UnsupportedOperationException(
        "Claims-map check not supported by this AuthorizationCheckPort implementation.");
  }
}
