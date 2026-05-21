/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.port.out.MembershipPort;
import java.util.Optional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

public final class UsernamePasswordAuthenticationTokenConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private final MembershipPort membershipPort;

  public UsernamePasswordAuthenticationTokenConverter(final MembershipPort membershipPort) {
    this.membershipPort = membershipPort;
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
    final var memberships = membershipPort.createProviderForUser(username);
    // BASIC auth has no token claims and never produces CLIENT principals; mappingRulesSupplier
    // is deliberately not wired so authenticatedMappingRuleIds() returns the record's default
    // empty list without invoking the provider.
    return CamundaAuthentication.of(
        a ->
            a.user(username)
                .groupIdsSupplier(memberships::groups)
                .roleIdsSupplier(memberships::roles)
                .tenantsSupplier(memberships::tenants));
  }
}
