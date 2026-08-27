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
   */
  <T> Either<AuthorizationRejection, Void> check(
      Map<String, Object> claims, RequiredAuthorization<T> authorization);

  /**
   * Property-based authorization check. The principal is authorized to access the concrete {@code
   * resource} instance when it holds a stored property-scoped grant for a property declared in
   * {@code authorization}, <em>and</em> the evaluator registered for that property matches {@code
   * resource}. Evaluators are looked up by property name; matching the resource is what the
   * selected evaluator then does.
   *
   * <p>Distinct from the scope-based {@link #check(CamundaAuthentication, RequiredAuthorization)}:
   * property-based authorization requires the concrete resource instance to evaluate the property
   * against. Lifting it onto the port (rather than only the concrete implementation) lets consumers
   * that need property checks depend on this interface instead of the implementation type. See
   * ADR-0014.
   *
   * @param authentication the resolved authentication context of the caller
   * @param authorization the authorization requirement declaring resource property names
   * @param resource the resource instance to evaluate declared properties against
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} otherwise
   */
  <T> Either<AuthorizationRejection, Void> check(
      CamundaAuthentication authentication, RequiredAuthorization<T> authorization, T resource);
}
