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
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public final class TokenClaimsConverter {

  private final OidcPrincipalLoader oidcPrincipalLoader;
  private final boolean preferUsernameClaim;
  private final String usernameClaim;
  private final String clientIdClaim;
  private final MembershipPort membershipPort;

  public TokenClaimsConverter(
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
          new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT),
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

    final var memberships =
        membershipPort.resolveMemberships(tokenClaims, principalName, principalType);

    return CamundaAuthentication.of(
        a -> {
          if (principalType == PrincipalType.CLIENT) {
            a.clientId(principalName);
          } else {
            a.user(principalName);
          }
          return a.groupIds(memberships.groups().groupIds())
              .roleIds(memberships.roles().roleIds())
              .tenants(memberships.tenants().tenantIds())
              .mappingRules(memberships.mappingRules().mappingRuleIds())
              .claims(tokenClaims);
        });
  }
}
