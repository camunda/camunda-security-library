/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.oidc.OidcPrincipalLoader;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
import io.camunda.security.core.port.out.MembershipQuery;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Converts OIDC token claims into a {@link CamundaAuthentication} with lazily-resolved membership
 * fields. The converter wires four chained {@link LazyList} instances — each backed by one {@link
 * MembershipPort} method and capturing a reference to the upstream lists — so each membership type
 * is resolved only when its field is first read, and the chain runs at most once per step.
 */
public final class LazyTokenClaimsConverter {

  private final OidcPrincipalLoader oidcPrincipalLoader;
  private final boolean preferUsernameClaim;
  private final String usernameClaim;
  private final String clientIdClaim;
  private final MembershipPort membershipPort;

  public LazyTokenClaimsConverter(
      final OidcConfiguration oidcConfiguration, final MembershipPort membershipPort) {
    this.membershipPort = membershipPort;
    usernameClaim = oidcConfiguration.getUsernameClaim();
    clientIdClaim = oidcConfiguration.getClientIdClaim();
    preferUsernameClaim = oidcConfiguration.isPreferUsernameClaim();
    oidcPrincipalLoader = new OidcPrincipalLoader(usernameClaim, clientIdClaim);
  }

  public CamundaAuthentication convert(final Map<String, Object> tokenClaims) {
    final var principals = oidcPrincipalLoader.load(tokenClaims);
    final var username = principals.username();
    final var clientId = principals.clientId();

    if (username == null && clientId == null) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN),
          "Neither username claim (%s) nor clientId claim (%s) could be found in the claims."
              .formatted(usernameClaim, clientIdClaim));
    }

    final String principalName;
    final PrincipalType principalType;
    if ((preferUsernameClaim && username != null) || clientId == null) {
      principalName = username;
      principalType = PrincipalType.USER;
    } else {
      principalName = clientId;
      principalType = PrincipalType.CLIENT;
    }

    final var base = new MembershipQuery(tokenClaims, principalName, principalType);
    final var lazyMR = CamundaAuthentication.lazyList(() -> membershipPort.mappingRuleIds(base));
    final var lazyG =
        CamundaAuthentication.lazyList(
            () -> membershipPort.groupIds(base.withMappingRuleIds(lazyMR)));
    final var lazyR =
        CamundaAuthentication.lazyList(
            () -> membershipPort.roleIds(base.withMappingRuleIds(lazyMR).withGroupIds(lazyG)));
    final var lazyT =
        CamundaAuthentication.lazyList(
            () ->
                membershipPort.tenantIds(
                    base.withMappingRuleIds(lazyMR).withGroupIds(lazyG).withRoleIds(lazyR)));

    return CamundaAuthentication.of(
        a -> {
          if (principalType == PrincipalType.CLIENT) {
            a.clientId(principalName);
          } else {
            a.user(principalName);
          }
          return a.mappingRulesSupplier(() -> lazyMR)
              .groupIdsSupplier(() -> lazyG)
              .roleIdsSupplier(() -> lazyR)
              .tenantsSupplier(() -> lazyT)
              .claims(tokenClaims);
        });
  }
}
