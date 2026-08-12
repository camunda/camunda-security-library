/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
import io.camunda.security.core.port.out.MembershipQuery;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

public final class LazyUsernamePasswordAuthenticationTokenConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private final MembershipPort membershipPort;
  private final MembershipResolutionContextPropagator contextPropagator;

  public LazyUsernamePasswordAuthenticationTokenConverter(final MembershipPort membershipPort) {
    this(membershipPort, MembershipResolutionContextPropagator.identity());
  }

  public LazyUsernamePasswordAuthenticationTokenConverter(
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    this.membershipPort = Objects.requireNonNull(membershipPort, "membershipPort");
    this.contextPropagator = Objects.requireNonNull(contextPropagator, "contextPropagator");
  }

  @Override
  public boolean supports(final Authentication authentication) {
    return Optional.ofNullable(authentication)
        .filter(UsernamePasswordAuthenticationToken.class::isInstance)
        .isPresent();
  }

  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    final var username = authentication.getName();
    // BASIC auth has no token claims and never produces CLIENT principals. Empty claims means
    // mappingRuleIds() would return an empty list (no rules can match), so mappingRulesSupplier
    // is deliberately not wired — authenticatedMappingRuleIds() returns the record default.
    // (Only 3 lazy suppliers here vs. LazyTokenClaimsConverter's 4 — intentional, not a missed
    // decoration.)
    final var base = new MembershipQuery(Map.of(), username, PrincipalType.USER);
    final var lazyGroupIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(() -> membershipPort.groupIds(base)));
    final var lazyRoleIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(
                () -> membershipPort.roleIds(base.withGroupIds(lazyGroupIds))));
    final var lazyTenantIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(
                () ->
                    membershipPort.tenantIds(
                        base.withGroupIds(lazyGroupIds).withRoleIds(lazyRoleIds))));

    return CamundaAuthentication.of(
        a ->
            a.user(username)
                .groupIdsSupplier(() -> lazyGroupIds)
                .roleIdsSupplier(() -> lazyRoleIds)
                .tenantsSupplier(() -> lazyTenantIds));
  }
}
