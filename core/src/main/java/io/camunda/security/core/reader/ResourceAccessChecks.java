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

public record ResourceAccessChecks(
    AuthorizationCheck authorizationCheck,
    TenantCheck tenantCheck,
    CamundaAuthentication authentication) {

  public static ResourceAccessChecks disabled() {
    return new ResourceAccessChecks(
        AuthorizationCheck.disabled(), TenantCheck.disabled(), CamundaAuthentication.none());
  }

  public static ResourceAccessChecks of(
      final AuthorizationCheck authorizationCheck, final TenantCheck tenantCheck) {
    return new ResourceAccessChecks(authorizationCheck, tenantCheck, CamundaAuthentication.none());
  }

  public static ResourceAccessChecks of(
      final AuthorizationCheck authorizationCheck,
      final TenantCheck tenantCheck,
      final CamundaAuthentication authentication) {
    return new ResourceAccessChecks(authorizationCheck, tenantCheck, authentication);
  }

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

  public List<String> getAuthorizedTenantIds() {
    if (!tenantCheck.hasAnyTenantAccess()) {
      return Collections.emptyList();
    }
    return tenantCheck.tenantIds();
  }
}
