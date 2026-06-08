/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The complete access-control picture for a single query or get operation, combining resource-level
 * authorization ({@link AuthorizationCheck}) and tenant-level scoping ({@link TenantCheck}) with
 * the resolved {@link CamundaAuthentication} of the caller.
 *
 * <p>Search backends receive a {@code ResourceAccessChecks} from a {@link ResourceAccessController}
 * and translate it into backend-specific query predicates (e.g. Elasticsearch filters, SQL WHERE
 * clauses). The three computed views — {@link #getAuthorizedResourceIdsByType()}, {@link
 * #getAuthorizedResourcePropertyNamesByType()}, and {@link #getAuthorizedTenantIds()} — are the
 * primary inputs for those translations.
 *
 * <p>Use {@link #disabled()} for contexts where both authorization and tenant isolation are turned
 * off (e.g. internal system queries that must bypass access control).
 */
public record ResourceAccessChecks(
    AuthorizationCheck authorizationCheck,
    TenantCheck tenantCheck,
    CamundaAuthentication authentication) {

  /**
   * Creates a fully disabled instance with both authorization and tenant checks bypassed. Intended
   * for internal queries that must not be filtered by access control (e.g. port adapter calls that
   * back the authorization store itself).
   */
  public static ResourceAccessChecks disabled() {
    return new ResourceAccessChecks(
        AuthorizationCheck.disabled(), TenantCheck.disabled(), CamundaAuthentication.none());
  }

  /**
   * Creates an instance with the given checks and no authentication context. Suitable when the
   * authentication is not needed downstream (e.g. pre-resolved checks).
   */
  public static ResourceAccessChecks of(
      final AuthorizationCheck authorizationCheck, final TenantCheck tenantCheck) {
    return new ResourceAccessChecks(authorizationCheck, tenantCheck, CamundaAuthentication.none());
  }

  /**
   * Creates an instance with the given checks and the resolved authentication context. Use this
   * overload when the downstream backend needs to inspect the caller's identity (e.g. for
   * property-based access decisions).
   */
  public static ResourceAccessChecks of(
      final AuthorizationCheck authorizationCheck,
      final TenantCheck tenantCheck,
      final CamundaAuthentication authentication) {
    return new ResourceAccessChecks(authorizationCheck, tenantCheck, authentication);
  }

  /**
   * Returns the authorized resource IDs grouped by resource type name, deduped in encounter order.
   * Returns an empty map when authorization is disabled or no resource IDs are present in the
   * underlying condition.
   */
  public Map<String, List<String>> getAuthorizedResourceIdsByType() {
    if (!authorizationCheck.enabled() || !authorizationCheck.hasAnyResourceAccess()) {
      return Collections.emptyMap();
    }
    final var auths = authorizationCheck.authorizationCondition().authorizations();
    return auths.stream()
        .filter(Objects::nonNull)
        .filter(auth -> auth.resourceType() != null)
        .filter(RequiredAuthorization::hasAnyResourceIds)
        .collect(
            Collectors.groupingBy(
                auth -> auth.resourceType().name(),
                Collectors.collectingAndThen(
                    Collectors.flatMapping(
                        auth -> auth.resourceIds().stream(),
                        Collectors.toCollection(LinkedHashSet::new)),
                    List::copyOf)));
  }

  /**
   * Returns the authorized resource property names grouped by resource type name. Returns an empty
   * map when authorization is disabled or no property names are present in the underlying
   * condition.
   */
  public Map<String, Set<String>> getAuthorizedResourcePropertyNamesByType() {
    if (!authorizationCheck.enabled() || !authorizationCheck.hasAnyResourceAccess()) {
      return Collections.emptyMap();
    }
    final var auths = authorizationCheck.authorizationCondition().authorizations();
    return auths.stream()
        .filter(Objects::nonNull)
        .filter(auth -> auth.resourceType() != null)
        .filter(RequiredAuthorization::hasAnyResourcePropertyNames)
        .collect(
            Collectors.groupingBy(
                auth -> auth.resourceType().name(),
                Collectors.flatMapping(
                    auth -> auth.resourcePropertyNames().stream(), Collectors.toSet())));
  }

  /**
   * Returns the tenant IDs the caller is permitted to access, or an empty list when tenant scoping
   * is disabled or no tenant IDs are present.
   */
  public List<String> getAuthorizedTenantIds() {
    if (!tenantCheck.hasAnyTenantAccess()) {
      return Collections.emptyList();
    }
    return tenantCheck.tenantIds();
  }
}
