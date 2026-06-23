/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link AuthorizationCheckPort}. Orchestrates two distinct evaluation
 * paths:
 *
 * <p><strong>Scope-based checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization)}): Delegates to {@link AuthorizationChecker}. Checks with {@link
 * AuthorizationResourceType#TENANT} resource type produce {@link AuthorizationRejection.Tenant};
 * all other resource types produce {@link AuthorizationRejection.Permission}. Tenant checks only
 * run when multi-tenancy is enabled; permission checks only run when authorization is enabled.
 *
 * <p><strong>Property-based checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization, Object)}): Delegates to the registered {@link
 * PropertyAuthorizationEvaluator} instances in {@link PropertyAuthorizationEvaluatorRegistry}.
 * There is no equivalent path in {@link AuthorizationChecker}. Callers must not bypass this method
 * for property-based authorization.
 *
 * <p>When both authorization and multi-tenancy checks are globally disabled, all check methods
 * short-circuit and return {@link Either#right(Object) Either.right(null)} without delegating. Use
 * {@link #skipChecks()} to query this condition before constructing expensive auth objects on hot
 * paths.
 */
public final class AuthorizationService implements AuthorizationCheckPort {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

  private final AuthorizationChecker authorizationChecker;
  private final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;
  private final boolean authorizationEnabled;
  private final boolean multiTenancyChecksEnabled;

  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled) {
    this.authorizationChecker =
        Objects.requireNonNull(authorizationChecker, "authorizationChecker");
    this.propertyEvaluatorRegistry =
        Objects.requireNonNull(propertyEvaluatorRegistry, "propertyEvaluatorRegistry");
    this.authorizationEnabled = authorizationEnabled;
    this.multiTenancyChecksEnabled = multiTenancyChecksEnabled;
  }

  /**
   * Returns {@code true} when both authorization and multi-tenancy checks are globally disabled.
   * Callers on the command hot path can use this to avoid constructing authentication objects
   * entirely.
   */
  public boolean skipChecks() {
    return !authorizationEnabled && !multiTenancyChecksEnabled;
  }

  /**
   * Scope-based authorization check. Evaluates each resource ID in {@code authorization} against
   * the principal's granted scopes via {@link AuthorizationChecker}.
   *
   * <p>Tenant resource-type checks ({@link AuthorizationResourceType#TENANT}) only run when
   * multi-tenancy is enabled; all other checks only run when authorization is enabled.
   *
   * @return {@link Either#right(Object) right(null)} when authorized or when the relevant flag is
   *     disabled; {@link Either#left(Object) left(rejection)} when the principal lacks access
   */
  @Override
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
    if (skipChecks()) {
      return Either.right(null);
    }

    final boolean isTenantCheck =
        AuthorizationResourceType.TENANT.equals(authorization.resourceType());

    if (isTenantCheck && !multiTenancyChecksEnabled) {
      return Either.right(null);
    }
    if (!isTenantCheck && !authorizationEnabled) {
      return Either.right(null);
    }

    if (!authorization.hasAnyResourceIds()) {
      return Either.right(null);
    }

    for (final String resourceId : authorization.resourceIds()) {
      final AuthorizationScope scope = AuthorizationScope.of(resourceId);
      if (!authorizationChecker.isAuthorized(scope, authentication, authorization)) {
        LOG.debug(
            "Authorization denied for principal on resource [{}:{}]",
            authorization.resourceType(),
            resourceId);
        if (isTenantCheck) {
          return Either.left(new AuthorizationRejection.Tenant(resourceId));
        }
        return Either.left(
            new AuthorizationRejection.Permission(
                authorization.resourceType(), authorization.permissionType(), resourceId));
      }
    }

    return Either.right(null);
  }

  /**
   * Property-based authorization check. Evaluates whether the principal is authorized to access
   * {@code resource} based on each property name declared in {@code authorization}.
   *
   * <p>Property names with no registered {@link PropertyAuthorizationEvaluator} are skipped. Only
   * runs when authorization is globally enabled.
   *
   * @param resource the resource instance to evaluate the property against
   * @return {@link Either#right(Object) right(null)} when authorized or when the relevant flag is
   *     disabled; {@link Either#left(Object) left(rejection)} when access is denied via a
   *     registered evaluator
   */
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    if (skipChecks() || !authorizationEnabled) {
      return Either.right(null);
    }

    if (!authorization.hasAnyResourcePropertyNames()) {
      return Either.right(null);
    }

    for (final String propertyName : authorization.resourcePropertyNames()) {
      final Optional<PropertyAuthorizationEvaluator<T>> maybeEvaluator =
          propertyEvaluatorRegistry.findEvaluator(propertyName);
      if (maybeEvaluator.isPresent()
          && !maybeEvaluator.get().isAuthorized(authentication, resource)) {
        LOG.debug(
            "Property-based authorization denied for principal on property [{}] of resource type [{}]",
            propertyName,
            authorization.resourceType());
        return Either.left(
            new AuthorizationRejection.Permission(
                authorization.resourceType(), authorization.permissionType(), propertyName));
      }
    }

    return Either.right(null);
  }
}
