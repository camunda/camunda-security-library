/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.auth;

import io.camunda.security.api.model.auth.MembershipPort.PrincipalType;
import java.util.List;
import java.util.Map;

/**
 * Immutable chain-state record passed to each {@link MembershipPort} method. Carries the
 * per-authentication context (token claims, principal identity) plus the IDs already resolved by
 * earlier steps in the {@code mappingRuleIds → groupIds → roleIds → tenantIds} chain. Each later
 * step sees a richer query than the previous one.
 *
 * <p>Use the three-arg constructor to start the chain (all resolved-IDs lists empty), then use the
 * {@code withX()} withers to grow it as each step completes.
 *
 * <p>The resolved-IDs fields may hold {@link java.util.List} instances that are still lazy at the
 * time the record is constructed; they are evaluated only when iterated by the host.
 */
public record MembershipQuery(
    Map<String, Object> tokenClaims,
    String principalId,
    PrincipalType principalType,
    List<String> resolvedMappingRuleIds,
    List<String> resolvedGroupIds,
    List<String> resolvedRoleIds) {

  /** Start-of-chain constructor — all resolved-IDs lists are empty. */
  public MembershipQuery(
      final Map<String, Object> tokenClaims,
      final String principalId,
      final PrincipalType principalType) {
    this(tokenClaims, principalId, principalType, List.of(), List.of(), List.of());
  }

  public MembershipQuery withMappingRuleIds(final List<String> ids) {
    return new MembershipQuery(
        tokenClaims, principalId, principalType, ids, resolvedGroupIds, resolvedRoleIds);
  }

  public MembershipQuery withGroupIds(final List<String> ids) {
    return new MembershipQuery(
        tokenClaims, principalId, principalType, resolvedMappingRuleIds, ids, resolvedRoleIds);
  }

  public MembershipQuery withRoleIds(final List<String> ids) {
    return new MembershipQuery(
        tokenClaims, principalId, principalType, resolvedMappingRuleIds, resolvedGroupIds, ids);
  }
}
