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
import io.camunda.security.api.context.TokenClaimsAuthenticationResolver;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link AuthorizationCheckPort}. Orchestrates three distinct evaluation
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
 * <p><strong>Conditional role checks</strong> ({@link #check(CamundaAuthentication,
 * RequiredAuthorization, Object)}, for a resource type with a registered {@link
 * ResourceAttributeExtractor}): the principal's roles are its global roles plus the roles of its
 * conditional memberships whose conditions the resource meets (ADR-0041). With these roles, the
 * check passes when the principal holds a grant on each resource ID, or a property grant that a
 * {@link PropertyAuthorizationEvaluator} matches. A resource without an ID gets no grant by ID. A
 * conditional membership that cannot be evaluated does not count. Conditional memberships never
 * count for a resource type without an extractor, in a check without a resource, or for the grants
 * by ID of a check with more than one resource ID, because the conditions describe only {@code
 * resource}. A denied {@link AuthorizationResourceType#TENANT} check by ID produces {@link
 * AuthorizationRejection.Tenant}, as on the scope-based path.
 *
 * <p>{@link #skipChecks()} is a hot-path convenience for callers: it returns {@code true} when both
 * authorization and multi-tenancy checks are globally disabled, so callers can avoid constructing
 * expensive authentication objects before invoking a check method.
 */
public final class AuthorizationService implements AuthorizationCheckPort {

  private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

  private final AuthorizationChecker authorizationChecker;
  private final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry;
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
        new ResourceAttributeExtractorRegistry(List.of()),
        authorizationEnabled,
        multiTenancyChecksEnabled,
        claimsResolver,
        latencyRecorder);
  }

  /**
   * Full-control constructor also accepting the {@link ResourceAttributeExtractorRegistry} for the
   * conditional role checks. A resource type with no extractor in it ignores conditional
   * memberships.
   */
  public AuthorizationService(
      final AuthorizationChecker authorizationChecker,
      final PropertyAuthorizationEvaluatorRegistry propertyEvaluatorRegistry,
      final ResourceAttributeExtractorRegistry attributeExtractorRegistry,
      final boolean authorizationEnabled,
      final boolean multiTenancyChecksEnabled,
      final TokenClaimsAuthenticationResolver claimsResolver,
      final AuthorizationCheckLatencyRecorder latencyRecorder) {
    this.authorizationChecker =
        Objects.requireNonNull(authorizationChecker, "authorizationChecker");
    this.propertyEvaluatorRegistry =
        Objects.requireNonNull(propertyEvaluatorRegistry, "propertyEvaluatorRegistry");
    this.attributeExtractorRegistry =
        Objects.requireNonNull(attributeExtractorRegistry, "attributeExtractorRegistry");
    conditionalRoleEvaluator = new ConditionalRoleEvaluator(attributeExtractorRegistry);
    this.claimsResolver = Objects.requireNonNull(claimsResolver, "claimsResolver");
    this.latencyRecorder = Objects.requireNonNull(latencyRecorder, "latencyRecorder");
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
    } finally {
      recordLatencySafely(startNanos);
    }
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
   * <p>If a {@link ResourceAttributeExtractor} is registered for the resource type of {@code
   * authorization}, the conditional role check described in the class documentation runs instead.
   *
   * @param resource the resource instance to evaluate the property against; on the conditional role
   *     check, also the source of the resource attributes and of the resource ID
   * @return {@link Either#right(Object) right(null)} when authorized or when authorization is
   *     disabled; {@link Either#left(Object) left(rejection)} otherwise. On the conditional role
   *     check, a resource without an ID gives a {@link AuthorizationRejection.Permission} (or
   *     {@link AuthorizationRejection.Tenant} for {@link AuthorizationResourceType#TENANT}) with a
   *     {@code null} resource ID.
   * @throws IllegalArgumentException on the conditional role check if {@code authorization} has no
   *     resource IDs, no {@code resourceIdSupplier} and no resource property names
   * @throws NullPointerException on the conditional role check if {@code resource} is {@code null}
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

      if (attributeExtractorRegistry.hasExtractorsFor(authorization.resourceType())) {
        return checkConditionalRoles(authentication, authorization, resource);
      }

      if (!authorization.hasAnyResourcePropertyNames()) {
        return Either.right(null);
      }

      final List<AuthorizationScope> grantedPropertyScopes =
          authorizationChecker.retrieveAuthorizedPropertyScopes(
              authentication, authorization, authorization.resourcePropertyNames());
      if (isGrantedByProperty(authentication, resource, grantedPropertyScopes)) {
        return Either.right(null);
      }

      final Set<String> sortedDeclaredPropertyNames =
          new TreeSet<>(authorization.resourcePropertyNames());

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

  private <T> Either<AuthorizationRejection, Void> checkConditionalRoles(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> authorization,
      final T resource) {
    Objects.requireNonNull(resource, "resource");
    final boolean checksResourceIds =
        authorization.hasAnyResourceIds() || authorization.resourceIdSupplier() != null;
    if (!checksResourceIds && !authorization.hasAnyResourcePropertyNames()) {
      throw new IllegalArgumentException(
          ("A check on resource type %s, which has a ResourceAttributeExtractor, needs resource IDs,"
                  + " a resourceIdSupplier or resource property names")
              .formatted(authorization.resourceType()));
    }
    final Set<String> conditionalRoleIds =
        conditionalRoleEvaluator.applicableRoleIds(
            authentication, authorization.resourceType(), resource);

    // Empty when the resourceIdSupplier finds no ID; such a resource gets no grant by ID.
    final List<String> resourceIds = resourceIdsOf(authorization, resource);
    // The conditions were evaluated against one resource, so they say nothing about the other IDs
    // of a multi-ID check. There, only global roles count (ADR-0041 D4).
    final Set<String> idConditionalRoleIds =
        resourceIds.size() == 1 ? conditionalRoleIds : Set.of();
    final String deniedResourceId =
        resourceIds.stream()
            .filter(
                resourceId ->
                    !authorizationChecker.isAuthorized(
                        AuthorizationScope.of(resourceId),
                        authentication,
                        authorization,
                        idConditionalRoleIds))
            .findFirst()
            .orElse(null);
    if (!resourceIds.isEmpty() && deniedResourceId == null) {
      return Either.right(null);
    }
    if (authorization.hasAnyResourcePropertyNames()
        && isGrantedByProperty(
            authentication,
            resource,
            authorizationChecker.retrieveAuthorizedPropertyScopes(
                authentication,
                authorization,
                authorization.resourcePropertyNames(),
                conditionalRoleIds))) {
      return Either.right(null);
    }

    LOG.debug(
        "Authorization denied for [{}] on [{}:{}] with {} applicable conditional role(s)",
        principalType(authentication),
        authorization.resourceType(),
        authorization.permissionType(),
        conditionalRoleIds.size());
    if (checksResourceIds
        && AuthorizationResourceType.TENANT.equals(authorization.resourceType())) {
      return Either.left(new AuthorizationRejection.Tenant(deniedResourceId));
    }
    if (checksResourceIds) {
      return Either.left(
          new AuthorizationRejection.Permission(
              authorization.resourceType(), authorization.permissionType(), deniedResourceId));
    }
    return Either.left(
        new AuthorizationRejection.Property(
            authorization.resourceType(),
            authorization.permissionType(),
            new TreeSet<>(authorization.resourcePropertyNames())));
  }

  private static <T> List<String> resourceIdsOf(
      final RequiredAuthorization<T> authorization, final T resource) {
    if (authorization.hasAnyResourceIds()) {
      return authorization.resourceIds();
    }
    if (authorization.resourceIdSupplier() == null) {
      return List.of();
    }
    final String resourceId = authorization.resourceIdSupplier().apply(resource);
    return resourceId == null ? List.of() : List.of(resourceId);
  }

  /** Whether a property evaluator matches {@code resource} for one of the granted scopes. */
  private <T> boolean isGrantedByProperty(
      final CamundaAuthentication authentication,
      final T resource,
      final List<AuthorizationScope> grantedPropertyScopes) {
    for (final AuthorizationScope scope : grantedPropertyScopes) {
      final Optional<PropertyAuthorizationEvaluator<T>> maybeEvaluator =
          propertyEvaluatorRegistry.findEvaluator(scope.getResourcePropertyName());
      if (maybeEvaluator.isPresent()
          && maybeEvaluator.get().isAuthorized(authentication, resource)) {
        return true;
      }
    }
    return false;
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
