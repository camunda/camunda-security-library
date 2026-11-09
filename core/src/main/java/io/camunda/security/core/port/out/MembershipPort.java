/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.authz.ConditionalMembership;
import java.util.List;

/**
 * Outbound port the host implements to resolve a principal's memberships. The library calls each
 * method only when the corresponding membership field is actually read from the produced {@link
 * io.camunda.security.api.model.CamundaAuthentication}; the lazy evaluation and chain wiring are
 * owned by the library's converters — host implementations are stateless and just answer "given
 * this query context, return the IDs of this kind".
 *
 * <p>The {@link MembershipQuery} grows through the chain:
 *
 * <ul>
 *   <li>{@link #mappingRuleIds(MembershipQuery)} receives only the base context.
 *   <li>{@link #groupIds(MembershipQuery)} additionally receives the resolved mapping-rule IDs.
 *   <li>{@link #roleIds(MembershipQuery)} additionally receives the resolved group IDs.
 *   <li>{@link #tenantIds(MembershipQuery)} additionally receives the resolved role IDs.
 *   <li>{@link #conditionalRoleMemberships(MembershipQuery)} receives the same query as {@link
 *       #roleIds(MembershipQuery)}.
 * </ul>
 *
 * <p>The resolved-IDs fields on the query may hold lazy lists that materialise on first iteration;
 * hosts should treat them as ordinary {@code List<String>} values.
 */
public interface MembershipPort {

  List<String> mappingRuleIds(MembershipQuery query);

  List<String> groupIds(MembershipQuery query);

  List<String> roleIds(MembershipQuery query);

  List<String> tenantIds(MembershipQuery query);

  /**
   * Returns the principal's role memberships that apply only to resources meeting their conditions
   * (ADR-0041). They come in addition to {@link #roleIds(MembershipQuery)} and must not repeat a
   * global membership. Hosts without conditional memberships keep the default, which returns none.
   */
  default List<ConditionalMembership> conditionalRoleMemberships(final MembershipQuery query) {
    return List.of();
  }

  /** Identity type of the authenticated principal. */
  enum PrincipalType {
    USER,
    CLIENT
  }
}
