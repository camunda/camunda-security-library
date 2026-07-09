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
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link AuthorizationCheckPort}. Orchestrates two distinct evaluation
 * paths:
 *
 * <p><strong>Scope-based checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization)}): Delegates to {@link AuthorizationChecker}. Every check routed through
 * this method is an RBAC check gated on {@code authorizationEnabled}. Checks with {@link
 * AuthorizationResourceType#TENANT} resource type are RBAC on tenant <em>entities</em> (create /
 * update / delete a tenant, add / remove members) and produce {@link
 * AuthorizationRejection.Tenant}; all other resource types produce {@link
 * AuthorizationRejection.Permission}. This is <em>not</em> the tenant-membership dimension ("may
 * this principal act within tenant X"), which is handled separately by {@code TenantAccessProvider}
 * / {@code TenantCheck} and does not flow through this port. See ADR-0030 and issue #486.
 *
 * <p><strong>Property-based checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization, Object)}): Delegates to the registered {@link
 * PropertyAuthorizationEvaluator} instances in {@link PropertyAuthorizationEvaluatorRegistry}.
 * There is no equivalent path in {@link AuthorizationChecker}. Callers must not bypass this method
 * for property-based authorization.
 *
 * <p>{@link #skipChecks()} is a hot-path convenience for callers: it returns {@code true} when both
 * authorization and multi-tenancy checks are globally disabled, so callers can avoid constructing
 * expensive authentication objects before invoking a check method.
 */
public final class AuthorizationService implements AuthorizationCheckPort {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

  private final AuthorizationChecker authorizationChecker;
  private final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;
  private final boolean authorizationEnabled;
  private final boolean multiTenancyChecksEnabled;

  private final LazyTokenClaimsConverter claimsConverter;

  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final LazyTokenClaimsConverter claimsConverter) {
    this.authorizationChecker =
        Objects.requireNonNull(authorizationChecker, "authorizationChecker");
    this.propertyEvaluatorRegistry =
        Objects.requireNonNull(propertyEvaluatorRegistry, "propertyEvaluatorRegistry");
    this.claimsConverter = Objects.requireNonNull(claimsConverter, "claimsConverter");
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

  @Override
  public <T> Either<AuthorizationRejection, Void> check(
      final Map<String, Object> claims, final RequiredAuthorization<T> authorization) {
    if (!authorizationEnabled) {
      return Either.right(null);
    }

    if (!authorization.hasAnyResourceIds()) {
      return Either.right(null);
    }

    return check(claimsConverter.convert(claims), authorization);
  }

  /**
   * Scope-based authorization check. Evaluates each resource ID in {@code authorization} against
   * the principal's granted scopes via {@link AuthorizationChecker}.
   *
   * <p>This is an RBAC check gated on {@code authorizationEnabled}, for every resource type
   * including {@link AuthorizationResourceType#TENANT} (which represents RBAC on tenant entities,
   * not tenant membership). The tenant-membership dimension is handled separately by {@code
   * TenantAccessProvider} / {@code TenantCheck} and does not flow through this port. See ADR-0030
   * and issue #486.
   *
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} when the principal lacks access
   */
  @Override
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
    if (!authorizationEnabled) {
      return Either.right(null);
    }

    if (!authorization.hasAnyResourceIds()) {
      return Either.right(null);
    }

    final boolean isTenantResource =
        AuthorizationResourceType.TENANT.equals(authorization.resourceType());

    for (final String resourceId : authorization.resourceIds()) {
      final AuthorizationScope scope = AuthorizationScope.of(resourceId);
      if (!authorizationChecker.isAuthorized(scope, authentication, authorization)) {
        LOG.debug(
            "Authorization denied for [{}] on resource [{}:{}:{}]",
            principalType(authentication),
            authorization.resourceType(),
            authorization.permissionType(),
            resourceId);
        if (isTenantResource) {
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
   * Property-based authorization check. The principal is authorized to access {@code resource} when
   * it holds a <em>stored</em> property-scoped grant for the {@code authorization}'s resource type
   * and permission whose property is declared in {@code authorization}, <em>and</em> the registered
   * {@link PropertyAuthorizationEvaluator} for that property matches {@code resource}.
   *
   * <p>Both conditions are required: a stored property-scoped grant alone does not authorize (the
   * evaluator must match the concrete resource), and a matching evaluator alone does not authorize
   * (the principal must actually hold the property-scoped grant). This closes the gap where a
   * value-only evaluation authorized any principal that happened to match the resource property,
   * regardless of the permissions it was granted.
   *
   * <p>Only stored scopes with matcher {@link AuthorizationResourceMatcher#PROPERTY} participate;
   * id- and wildcard-scoped grants are evaluated by {@link #check(CamundaAuthentication,
   * RequiredAuthorization)}. Granted properties not declared in {@code authorization}, and declared
   * properties with no registered evaluator, do not authorize. Only runs when authorization is
   * globally enabled.
   *
   * @param resource the resource instance to evaluate the property against
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} otherwise
   */
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    if (!authorizationEnabled) {
      return Either.right(null);
    }

    if (!authorization.hasAnyResourcePropertyNames()) {
      return Either.right(null);
    }

    final Set<String> declaredPropertyNames = authorization.resourcePropertyNames();
    final List<AuthorizationScope> grantedScopes =
        authorizationChecker.retrieveAuthorizedAuthorizationScopes(authentication, authorization);

    for (final AuthorizationScope scope : grantedScopes) {
      if (scope.getMatcher() != AuthorizationResourceMatcher.PROPERTY) {
        continue;
      }
      final String propertyName = scope.getResourcePropertyName();
      if (!declaredPropertyNames.contains(propertyName)) {
        continue;
      }
      final Optional<PropertyAuthorizationEvaluator<T>> maybeEvaluator =
          propertyEvaluatorRegistry.findEvaluator(propertyName);
      if (maybeEvaluator.isPresent()
          && maybeEvaluator.get().isAuthorized(authentication, resource)) {
        return Either.right(null);
      }
    }

    final String sortedDeclaredPropertyNames =
        String.join(",", new TreeSet<>(declaredPropertyNames));

    LOG.debug(
        "Property-based authorization denied for [{}] on [{}] properties {} of resource type [{}]",
        principalType(authentication),
        authorization.permissionType(),
        sortedDeclaredPropertyNames,
        authorization.resourceType());
    return Either.left(
        new AuthorizationRejection.Permission(
            authorization.resourceType(),
            authorization.permissionType(),
            sortedDeclaredPropertyNames));
  }

  private static String principalType(final CamundaAuthentication authentication) {
    if (authentication.isAnonymous()) {
      return "anonymous";
    }
    if (authentication.authenticatedUsername() != null) {
      return "user";
    }
    if (authentication.authenticatedClientId() != null) {
      return "client";
    }
    return "unknown";
  }
}
