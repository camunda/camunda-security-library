/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.AuthorizationScope;
import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.core.auth.RequiredAuthorization;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A generic {@link ResourceAccessProvider} for resource types that declare attributes. It computes
 * a {@link ResourceAccessFilter} from the grants of the principal, so that a host can translate
 * "which resources may this principal access" into a query, and evaluates a single resource by the
 * same rule as {@link AuthorizationService}. The filter terms come from:
 *
 * <ul>
 *   <li>grants on all resources, held directly or through unconditional roles: access to all;
 *   <li>grants on resource IDs: a term with those IDs;
 *   <li>property grants of the requested properties: a term with the principal condition they stand
 *       for, resolved to the values of the principal;
 *   <li>the same three kinds of grants of the roles of the principal's {@link RoleMembership}s,
 *       each term restricted by the conditions of the membership.
 * </ul>
 *
 * <p>An authorization that asks for property grants only, see {@code ResourceConditions}, ignores
 * grants on resource IDs, like the check does. Role memberships only take part for resource types
 * that have a {@link ResourceAttributeExtractor}. Terms that can never match, because a condition
 * has no values or refers to an attribute the type does not declare, are dropped. This provider has
 * no property matchers: a resource of a type without extractor is denied if properties are
 * requested.
 *
 * <p>Property grants only take part for resource types that have an attribute extractor, so that
 * the list agrees with the single check, which evaluates property grants of other types through
 * property evaluators.
 *
 * <p>The grants of each conditional role are read with one query, so resolving access takes one
 * query per distinct role of the principal.
 */
public final class ConditionalResourceAccessProvider implements ResourceAccessProvider {

  private static final Logger LOG =
      LoggerFactory.getLogger(ConditionalResourceAccessProvider.class);

  private final AuthorizationChecker authorizationChecker;
  private final ResourceAttributeExtractorRegistry attributeExtractorRegistry;
  private final ConditionalRoleEvaluator conditionalRoleEvaluator;

  public ConditionalResourceAccessProvider(
      final AuthorizationChecker authorizationChecker,
      final ResourceAttributeExtractorRegistry attributeExtractorRegistry) {
    this.authorizationChecker = authorizationChecker;
    this.attributeExtractorRegistry = attributeExtractorRegistry;
    conditionalRoleEvaluator =
        new ConditionalRoleEvaluator(authorizationChecker, attributeExtractorRegistry);
  }

  /**
   * Builds a provider from the host's {@link AuthorizationScopeRepositoryPort}, or a {@link
   * DisabledResourceAccessProvider} when {@code authorizationEnabled} is {@code false}.
   */
  public static ResourceAccessProvider forScopeRepository(
      final AuthorizationScopeRepositoryPort scopeRepository,
      final ResourceAttributeExtractorRegistry attributeExtractorRegistry,
      final boolean authorizationEnabled) {
    return authorizationEnabled
        ? new ConditionalResourceAccessProvider(
            new AuthorizationChecker(scopeRepository), attributeExtractorRegistry)
        : new DisabledResourceAccessProvider();
  }

  @Override
  public <T> ResourceAccess resolveResourceAccess(
      final CamundaAuthentication authentication, final RequiredAuthorization<T> authorization) {
    final var terms =
        new TermCollector(
            authentication,
            authorization,
            attributeExtractorRegistry.hasExtractorsFor(authorization.resourceType()));
    terms.addGrants(
        authorizationChecker.retrieveAuthorizedAuthorizationScopes(authentication, authorization),
        List.of());

    if (attributeExtractorRegistry.hasExtractorsFor(authorization.resourceType())) {
      final Map<String, List<AuthorizationScope>> scopesByRole = new HashMap<>();
      for (final RoleMembership membership : authentication.roleMemberships()) {
        final var scopes =
            scopesByRole.computeIfAbsent(
                membership.roleId(),
                roleId ->
                    authorizationChecker.retrieveAuthorizedAuthorizationScopesOfRole(
                        roleId, authorization));
        terms.addGrants(scopes, membership.conditions());
      }
    }
    return terms.toResourceAccess();
  }

  @Override
  public <T> ResourceAccess hasResourceAccess(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> requiredAuthorization,
      final T resource) {
    final var resourceType = requiredAuthorization.resourceType();
    if (attributeExtractorRegistry.hasExtractorsFor(resourceType)) {
      if (attributeExtractorRegistry.findMatching(resourceType, resource).isEmpty()) {
        LOG.debug(
            "No attribute extractor found for resource class '{}' of resource type '{}'; denying"
                + " access.",
            resource.getClass().getSimpleName(),
            resourceType);
        return ResourceAccess.denied(requiredAuthorization);
      }
      final var decision =
          conditionalRoleEvaluator.evaluate(authentication, requiredAuthorization, resource);
      final var checked =
          decision.resourceId() == null
              ? requiredAuthorization
              : checkedAuthorization(requiredAuthorization, decision.resourceId());
      return decision.allowed() ? ResourceAccess.allowed(checked) : ResourceAccess.denied(checked);
    }

    if (requiredAuthorization.hasAnyResourcePropertyNames()) {
      LOG.debug(
          "No attribute extractor found for resource type '{}'; denying property-based access.",
          resourceType);
      return ResourceAccess.denied(requiredAuthorization);
    }
    return hasResourceAccessByResourceId(
        authentication,
        requiredAuthorization,
        ResourceIdResolver.resolveResourceId(requiredAuthorization, resource));
  }

  /**
   * Evaluates the access by ID with the principal's unconditional roles and direct grants. Grants
   * of roles with conditions need the resource, see {@link #hasResourceAccess}. Property grants are
   * not evaluated, as they need the attributes of the resource.
   */
  @Override
  public <T> ResourceAccess hasResourceAccessByResourceId(
      final CamundaAuthentication authentication,
      final RequiredAuthorization<T> requiredAuthorization,
      final String resourceId) {
    final Set<String> unconditionalRoleIds =
        attributeExtractorRegistry.hasExtractorsFor(requiredAuthorization.resourceType())
            ? conditionalRoleEvaluator.applicableRoleIds(authentication, Map.of())
            : Set.of();
    final var isAuthorized =
        authorizationChecker.isAuthorized(
            AuthorizationScope.of(resourceId),
            authentication,
            requiredAuthorization,
            unconditionalRoleIds);
    final var checked = checkedAuthorization(requiredAuthorization, resourceId);
    return isAuthorized ? ResourceAccess.allowed(checked) : ResourceAccess.denied(checked);
  }

  private static <T> RequiredAuthorization<T> checkedAuthorization(
      final RequiredAuthorization<T> requiredAuthorization, final String resourceId) {
    return RequiredAuthorization.of(
        a ->
            a.resourceType(requiredAuthorization.resourceType())
                .permissionType(requiredAuthorization.permissionType())
                .resourceIds(List.of(resourceId)));
  }

  private static final class TermCollector {

    private final CamundaAuthentication authentication;
    private final RequiredAuthorization<?> authorization;
    private final AuthorizationResourceType resourceType;
    private final boolean propertyGrantsApply;
    private final Set<Term> terms = new LinkedHashSet<>();
    private final Set<String> grantedPropertyNames = new LinkedHashSet<>();

    TermCollector(
        final CamundaAuthentication authentication,
        final RequiredAuthorization<?> authorization,
        final boolean propertyGrantsApply) {
      this.authentication = authentication;
      this.authorization = authorization;
      this.propertyGrantsApply = propertyGrantsApply;
      resourceType = authorization.resourceType();
    }

    void addGrants(final List<AuthorizationScope> scopes, final List<Condition> conditions) {
      final boolean propertyOnly = ResourceConditions.isPropertyOnly(authorization);
      final Set<String> resourceIds = new LinkedHashSet<>();
      for (final AuthorizationScope scope : scopes) {
        switch (scope.getMatcher()) {
          case ANY -> {
            if (!propertyOnly) {
              addTerm(Set.of(), conditions);
            }
          }
          case ID -> {
            if (!propertyOnly) {
              resourceIds.add(scope.getResourceId());
            }
          }
          case PROPERTY -> addPropertyGrant(scope.getResourcePropertyName(), conditions);
          default -> {}
        }
      }
      if (!resourceIds.isEmpty()) {
        addTerm(resourceIds, conditions);
      }
    }

    private void addPropertyGrant(final String propertyName, final List<Condition> conditions) {
      if (!propertyGrantsApply
          || !authorization.hasAnyResourcePropertyNames()
          || !authorization.resourcePropertyNames().contains(propertyName)) {
        return;
      }
      ResourceConditions.propertyCondition(resourceType, propertyName)
          .map(condition -> ResourceConditions.resolved(condition, authentication))
          .ifPresent(
              condition -> {
                final var all = new ArrayList<>(conditions);
                all.add(condition);
                if (addTerm(Set.of(), all)) {
                  grantedPropertyNames.add(propertyName);
                }
              });
    }

    private boolean addTerm(final Set<String> resourceIds, final List<Condition> conditions) {
      if (!isSatisfiable(conditions)) {
        return false;
      }
      terms.add(new Term(resourceIds, conditions));
      return true;
    }

    private boolean isSatisfiable(final List<Condition> conditions) {
      return conditions.stream()
          .allMatch(
              condition ->
                  resourceType.getSupportedAttributes().contains(condition.attribute())
                      && !ResourceConditions.resolve(condition.operand(), authentication)
                          .isEmpty());
    }

    ResourceAccess toResourceAccess() {
      if (terms.stream().anyMatch(Term::isUnrestricted)) {
        return ResourceAccess.wildcard(
            authorization.withResourceId(AuthorizationScope.WILDCARD_CHAR));
      }
      if (terms.isEmpty()) {
        return ResourceAccess.denied(authorization);
      }
      final RequiredAuthorization<?> resolved =
          authorization.hasAnyResourcePropertyNames()
              ? authorization.withResourcePropertyNames(grantedPropertyNames)
              : authorization;
      return ResourceAccess.allowed(
          resolved, new ResourceAccessFilter.AnyOf(mergeResourceIdTerms()));
    }

    private List<Term> mergeResourceIdTerms() {
      final Set<String> unconditionalIds = new HashSet<>();
      final List<Term> merged = new ArrayList<>();
      for (final Term term : terms) {
        if (term.conditions().isEmpty()) {
          unconditionalIds.addAll(term.resourceIds());
        } else {
          merged.add(term);
        }
      }
      if (!unconditionalIds.isEmpty()) {
        merged.addFirst(new Term(unconditionalIds, List.of()));
      }
      return merged;
    }
  }
}
