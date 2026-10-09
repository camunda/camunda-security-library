/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.ScopedRoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import java.util.stream.Collectors;
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
 * / {@code TenantCheck} and does not flow through this port. See ADR-0014 and issue #486.
 *
 * <p><strong>Property-based checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization, Object)}): Delegates to the registered {@link
 * PropertyAuthorizationEvaluator} instances in {@link PropertyAuthorizationEvaluatorRegistry}.
 * There is no equivalent path in {@link AuthorizationChecker}. Callers must not bypass this method
 * for property-based authorization.
 *
 * <p><strong>Scope-restricted role checks</strong> (same overload, for resource types with a
 * registered {@link ResourceScopeExtractor}): evaluates the resource IDs of the {@code
 * authorization} like the scope-based path, with the principal's roles extended by the roles of its
 * {@link ScopedRoleMembership}s whose scope ID equals the scope ID of the resource. Unlike the
 * scope-based path, the resource ID is derived from the resource by the {@code resourceIdSupplier}
 * of {@code authorization} (see {@link ResourceIdResolver}; the supplier returns the wildcard for
 * create-type checks), and explicit resource IDs are rejected. The scope of a single resource
 * object thus applies to one ID only; callers check multiple resources one at a time. It also fails
 * fast if {@code authorization} declares resource property names, as the property path is not
 * evaluated for such resource types.
 *
 * <p><strong>Conditional role checks</strong> (same overload, for resource types with a registered
 * {@link ResourceAttributeExtractor}): the resource ID is derived like for the scope-restricted
 * checks. The principal's roles are extended by the roles of its {@link
 * io.camunda.security.api.model.authz.RoleMembership}s whose conditions are all met by the
 * attributes of the resource. Property names of {@code authorization} are evaluated as principal
 * conditions against the attributes of the resource instead of through a {@link
 * PropertyAuthorizationEvaluator}.
 *
 * <p>{@link #skipChecks()} is a hot-path convenience for callers: it returns {@code true} when both
 * authorization and multi-tenancy checks are globally disabled, so callers can avoid constructing
 * expensive authentication objects before invoking a check method.
 */
public final class AuthorizationService implements AuthorizationCheckPort {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

  private final AuthorizationChecker authorizationChecker;
  private final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;
  private final ResourceScopeExtractorRegistry scopeExtractorRegistry;
  private final ResourceAttributeExtractorRegistry attributeExtractorRegistry;
  private final ConditionalRoleEvaluator conditionalRoleEvaluator;
  private final boolean authorizationEnabled;
  private final boolean multiTenancyChecksEnabled;

  private final TokenClaimsAuthenticationResolver claimsResolver;
  private final AuthorizationCheckLatencyRecorder latencyRecorder;
  private final AtomicBoolean latencyRecorderFailureLogged = new AtomicBoolean(false);

  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final TokenClaimsAuthenticationResolver claimsResolver) {
    this(
        authorizationChecker,
        propertyEvaluatorRegistry,
        authorizationEnabled,
        multiTenancyChecksEnabled,
        claimsResolver,
        AuthorizationCheckLatencyRecorder.noop());
  }

  /**
   * Full-control constructor also accepting an {@link AuthorizationCheckLatencyRecorder}. Only the
   * two terminal {@code check(...)} overloads (scope-based and property-based) are timed; see
   * {@link AuthorizationCheckLatencyRecorder} for why the claims-map overload is left untimed.
   */
  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final AuthorizationCheckLatencyRecorder latencyRecorder) {
    this(
        authorizationChecker,
        propertyEvaluatorRegistry,
        new ResourceScopeExtractorRegistry(List.of()),
        authorizationEnabled,
        multiTenancyChecksEnabled,
        claimsResolver,
        latencyRecorder);
  }

  /**
   * Full-control constructor also accepting the {@link ResourceScopeExtractorRegistry} of the
   * scope-restricted role checks, which read the principal's {@link
   * CamundaAuthentication#scopedRoleMemberships()}.
   */
  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final ResourceScopeExtractorRegistry scopeExtractorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final AuthorizationCheckLatencyRecorder latencyRecorder) {
    this(
        authorizationChecker,
        propertyEvaluatorRegistry,
        scopeExtractorRegistry,
        new ResourceAttributeExtractorRegistry(List.of()),
        authorizationEnabled,
        multiTenancyChecksEnabled,
        claimsResolver,
        latencyRecorder);
  }

  /**
   * Full-control constructor also accepting the {@link ResourceAttributeExtractorRegistry} of the
   * conditional role checks, which read the principal's {@link
   * CamundaAuthentication#roleMemberships()}.
   *
   * @throws IllegalStateException if a resource type has both a {@link ResourceScopeExtractor} and
   *     a {@link ResourceAttributeExtractor} for resource classes of which one is assignable to the
   *     other
   */
  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final ResourceScopeExtractorRegistry scopeExtractorRegistry,
      final ResourceAttributeExtractorRegistry attributeExtractorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final AuthorizationCheckLatencyRecorder latencyRecorder) {
    this.authorizationChecker =
        Objects.requireNonNull(authorizationChecker, "authorizationChecker");
    this.propertyEvaluatorRegistry =
        Objects.requireNonNull(propertyEvaluatorRegistry, "propertyEvaluatorRegistry");
    this.scopeExtractorRegistry =
        Objects.requireNonNull(scopeExtractorRegistry, "scopeExtractorRegistry");
    this.attributeExtractorRegistry =
        Objects.requireNonNull(attributeExtractorRegistry, "attributeExtractorRegistry");
    rejectOverlappingExtractors(scopeExtractorRegistry, attributeExtractorRegistry);
    conditionalRoleEvaluator =
        new ConditionalRoleEvaluator(authorizationChecker, attributeExtractorRegistry);
    this.claimsResolver = Objects.requireNonNull(claimsResolver, "claimsResolver");
    this.latencyRecorder = Objects.requireNonNull(latencyRecorder, "latencyRecorder");
    this.authorizationEnabled = authorizationEnabled;
    this.multiTenancyChecksEnabled = multiTenancyChecksEnabled;
  }

  private static void rejectOverlappingExtractors(
      final ResourceScopeExtractorRegistry scopeRegistry,
      final ResourceAttributeExtractorRegistry attributeRegistry) {
    final var overlap = new ArrayList<List<Object>>();
    for (final var scope : scopeRegistry.registrations()) {
      for (final var attribute : attributeRegistry.registrations()) {
        if (scope.get(0).equals(attribute.get(0))
            && classesOverlap(scope.get(1), attribute.get(1))) {
          overlap.add(List.of(scope.get(0), scope.get(1), attribute.get(1)));
        }
      }
    }
    if (!overlap.isEmpty()) {
      throw new IllegalStateException(
          "Each (resource type, resource class) may have either a ResourceScopeExtractor or a"
              + " ResourceAttributeExtractor, but both are registered for "
              + overlap);
    }
  }

  private static boolean classesOverlap(final Object first, final Object second) {
    return ((Class<?>) first).isAssignableFrom((Class<?>) second)
        || ((Class<?>) second).isAssignableFrom((Class<?>) first);
  }

  /**
   * Returns {@code true} when both authorization and multi-tenancy checks are globally disabled.
   * Callers on the command hot path can use this to avoid constructing authentication objects
   * entirely.
   */
  public boolean skipChecks() {
    return !authorizationEnabled && !multiTenancyChecksEnabled;
  }

  /** Exposed package-privately so tests can assert the shared-resolver wiring invariant. */
  TokenClaimsAuthenticationResolver claimsResolver() {
    return claimsResolver;
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

    return check(claimsResolver.resolve(claims), authorization);
  }

  /**
   * Scope-based authorization check. Evaluates each resource ID in {@code authorization} against
   * the principal's granted scopes via {@link AuthorizationChecker}.
   *
   * <p>This is an RBAC check gated on {@code authorizationEnabled}, for every resource type
   * including {@link AuthorizationResourceType#TENANT} (which represents RBAC on tenant entities,
   * not tenant membership). The tenant-membership dimension is handled separately by {@code
   * TenantAccessProvider} / {@code TenantCheck} and does not flow through this port. See ADR-0014
   * and issue #486.
   *
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} when the principal lacks access
   */
  @Override
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
    final long startNanos = System.nanoTime();
    try {
      if (!authorizationEnabled) {
        return Either.right(null);
      }

      if (!authorization.hasAnyResourceIds()) {
        return Either.right(null);
      }

      return checkResourceIds(
          authentication,
          authorization,
          scope -> authorizationChecker.isAuthorized(scope, authentication, authorization));
    } finally {
      recordLatencySafely(startNanos);
    }
  }

  private <T> Either<AuthorizationRejection, Void> checkResourceIds(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final Predicate<AuthorizationScope> isAuthorized) {
    final boolean isTenantResource =
        AuthorizationResourceType.TENANT.equals(authorization.resourceType());

    for (final String resourceId : authorization.resourceIds()) {
      final AuthorizationScope scope = AuthorizationScope.of(resourceId);
      if (!isAuthorized.test(scope)) {
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
   * <p>If a {@link ResourceScopeExtractor} or a {@link ResourceAttributeExtractor} is registered
   * for the resource type of {@code authorization}, the scope-restricted or conditional role check
   * described in the class documentation runs instead of the property path.
   *
   * @param resource the resource instance to evaluate the property against, or whose scope or
   *     attributes the scope-restricted or conditional role check uses
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} otherwise
   * @throws IllegalArgumentException on the scope-restricted and conditional paths if {@code
   *     authorization} has no {@code resourceIdSupplier} (unless it asks for property grants only
   *     on the conditional path), carries explicit resource IDs, or no extractor registered for the
   *     resource type accepts {@code resource}; on the scope-restricted path also if it declares
   *     resource property names
   * @throws NullPointerException on the scope-restricted and conditional paths if {@code resource}
   *     is {@code null}
   */
  @Override
  public <T> Either<AuthorizationRejection, Void> check(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    final long startNanos = System.nanoTime();
    try {
      if (!authorizationEnabled) {
        return Either.right(null);
      }

      if (hasExtractorsFor(authorization.resourceType())) {
        return checkWithExtractors(authentication, authorization, resource);
      }

      if (!authorization.hasAnyResourcePropertyNames()) {
        return Either.right(null);
      }

      final Set<String> declaredPropertyNames = authorization.resourcePropertyNames();
      final List<AuthorizationScope> grantedPropertyScopes =
          authorizationChecker.retrieveAuthorizedPropertyScopes(
              authentication, authorization, declaredPropertyNames);

      for (final AuthorizationScope scope : grantedPropertyScopes) {
        final String propertyName = scope.getResourcePropertyName();
        final Optional<PropertyAuthorizationEvaluator<T>> maybeEvaluator =
            propertyEvaluatorRegistry.findEvaluator(propertyName);
        if (maybeEvaluator.isPresent()
            && maybeEvaluator.get().isAuthorized(authentication, resource)) {
          return Either.right(null);
        }
      }

      final Set<String> sortedDeclaredPropertyNames = new TreeSet<>(declaredPropertyNames);

      LOG.debug(
          "Property-based authorization denied for [{}] on [{}] properties {} of resource type [{}]",
          principalType(authentication),
          authorization.permissionType(),
          sortedDeclaredPropertyNames,
          authorization.resourceType());
      return Either.left(
          new AuthorizationRejection.Property(
              authorization.resourceType(),
              authorization.permissionType(),
              sortedDeclaredPropertyNames));
    } finally {
      recordLatencySafely(startNanos);
    }
  }

  private boolean hasExtractorsFor(final AuthorizationResourceType resourceType) {
    return scopeExtractorRegistry.hasExtractorsFor(resourceType)
        || attributeExtractorRegistry.hasExtractorsFor(resourceType);
  }

  private <T> Either<AuthorizationRejection, Void> checkWithExtractors(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    Objects.requireNonNull(resource, "resource");
    final Optional<ResourceScopeExtractor<T>> scopeExtractor =
        scopeExtractorRegistry.findMatching(authorization.resourceType(), resource);
    if (scopeExtractor.isPresent()) {
      return checkScopedRoles(authentication, authorization, resource, scopeExtractor.get());
    }
    if (attributeExtractorRegistry
        .findMatching(authorization.resourceType(), resource)
        .isPresent()) {
      return checkConditionalRoles(authentication, authorization, resource);
    }
    throw new IllegalArgumentException(
        "No ResourceScopeExtractor or ResourceAttributeExtractor for resource type "
            + authorization.resourceType()
            + " accepts resource of class "
            + resource.getClass().getName());
  }

  private <T> Either<AuthorizationRejection, Void> checkConditionalRoles(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    final var decision = conditionalRoleEvaluator.evaluate(authentication, authorization, resource);
    if (decision.allowed()) {
      return Either.right(null);
    }
    LOG.debug(
        "Authorization denied for [{}] on [{}:{}] of a resource with conditional role memberships",
        principalType(authentication),
        authorization.resourceType(),
        authorization.permissionType());
    if (decision.resourceId() != null) {
      return Either.left(
          new AuthorizationRejection.Permission(
              authorization.resourceType(), authorization.permissionType(), decision.resourceId()));
    }
    return Either.left(
        new AuthorizationRejection.Property(
            authorization.resourceType(),
            authorization.permissionType(),
            new TreeSet<>(authorization.resourcePropertyNames())));
  }

  private <T> Either<AuthorizationRejection, Void> checkScopedRoles(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource,
      final ResourceScopeExtractor<T> scopeExtractor) {
    if (authorization.hasAnyResourcePropertyNames()) {
      throw new IllegalArgumentException(
          "Scope-restricted check on resource type "
              + authorization.resourceType()
              + " does not support resource property names");
    }

    final var resolvedAuthorization =
        authorization.withResourceId(ResourceIdResolver.resolveResourceId(authorization, resource));
    final String resourceScopeId = scopeExtractor.scopeIdOf(resource);
    final Set<String> scopedRoleIds =
        authentication.scopedRoleMemberships().stream()
            .filter(membership -> membership.scopeId().equals(resourceScopeId))
            .map(ScopedRoleMembership::roleId)
            .collect(Collectors.toSet());
    return checkResourceIds(
        authentication,
        resolvedAuthorization,
        scope ->
            authorizationChecker.isAuthorized(
                scope, authentication, resolvedAuthorization, scopedRoleIds));
  }

  private void recordLatencySafely(final long startNanos) {
    try {
      latencyRecorder.record(System.nanoTime() - startNanos);
    } catch (final RuntimeException e) {
      // Metrics failures must never affect authorization decisions. Logged once (not at every
      // call, since this runs on every authorization check) so a broken recorder isn't silently
      // invisible at default log levels.
      if (latencyRecorderFailureLogged.compareAndSet(false, true)) {
        LOG.warn(
            "Authorization-check latency recorder threw; suppressing further occurrences of this"
                + " warning",
            e);
      }
    }
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
