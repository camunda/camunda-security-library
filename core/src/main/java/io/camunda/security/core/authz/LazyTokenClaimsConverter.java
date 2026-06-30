/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.oidc.OidcPrincipalLoader;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
import io.camunda.security.core.port.out.MembershipQuery;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Converts a raw {@code Map<String, Object>} claims map into a {@link CamundaAuthentication} with
 * lazily-resolved membership fields via the four-step chain defined in {@link MembershipPort}.
 * Throws {@link IllegalArgumentException} (not a Spring type) when neither the username claim nor
 * the client-id claim resolves to a non-null string.
 *
 * <p>See ADR-0028 for why the constructor accepts primitive claim strings rather than {@code
 * OidcConfiguration}: it keeps {@code core} free of config-object coupling.
 */
public final class LazyTokenClaimsConverter {

  private final OidcPrincipalLoader oidcPrincipalLoader;
  private final boolean preferUsernameClaim;
  private final String usernameClaim;
  private final String clientIdClaim;
  private final MembershipPort membershipPort;
  private final MembershipResolutionContextPropagator contextPropagator;

  public LazyTokenClaimsConverter(
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim,
      final MembershipPort membershipPort) {
    this(
        usernameClaim,
        clientIdClaim,
        preferUsernameClaim,
        membershipPort,
        MembershipResolutionContextPropagator.identity());
  }

  public LazyTokenClaimsConverter(
      final String usernameClaim,
      final String clientIdClaim,
      final boolean preferUsernameClaim,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    this.usernameClaim = usernameClaim;
    this.clientIdClaim = clientIdClaim;
    this.preferUsernameClaim = preferUsernameClaim;
    this.membershipPort = Objects.requireNonNull(membershipPort, "membershipPort");
    this.contextPropagator = Objects.requireNonNull(contextPropagator, "contextPropagator");
    oidcPrincipalLoader = new OidcPrincipalLoader(usernameClaim, clientIdClaim);
  }

  public CamundaAuthentication convert(final Map<String, Object> claims) {
    final Map<String, Object> snapshotClaims =
        Collections.unmodifiableMap(
            new HashMap<>(claims)); // snapshot; lazy resolution sees a stable map
    final var principals = oidcPrincipalLoader.load(snapshotClaims);
    final var username = principals.username();
    final var clientId = principals.clientId();

    if (username == null && clientId == null) {
      throw new IllegalArgumentException(
          "Neither username claim (%s) nor clientId claim (%s) could be found in the claims."
              .formatted(
                  usernameClaim != null ? usernameClaim : "<not configured>",
                  clientIdClaim != null ? clientIdClaim : "<not configured>"));
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

    final var base = new MembershipQuery(snapshotClaims, principalName, principalType);
    // Each membership lookup is resolved lazily and may run after the request scope is gone (async
    // reads, session serialisation). The context propagator captures any host resolution context
    // now — while this converter runs in scope — and rebinds it around the deferred lookup.
    final var lazyMappingRuleIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(() -> membershipPort.mappingRuleIds(base)));
    final var lazyGroupIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(
                () -> membershipPort.groupIds(base.withMappingRuleIds(lazyMappingRuleIds))));
    final var lazyRoleIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(
                () ->
                    membershipPort.roleIds(
                        base.withMappingRuleIds(lazyMappingRuleIds).withGroupIds(lazyGroupIds))));
    final var lazyTenantIds =
        CamundaAuthentication.lazyList(
            contextPropagator.decorate(
                () ->
                    membershipPort.tenantIds(
                        base.withMappingRuleIds(lazyMappingRuleIds)
                            .withGroupIds(lazyGroupIds)
                            .withRoleIds(lazyRoleIds))));

    return CamundaAuthentication.of(
        a -> {
          if (principalType == PrincipalType.CLIENT) {
            a.clientId(principalName);
          } else {
            a.user(principalName);
          }
          return a.mappingRulesSupplier(() -> lazyMappingRuleIds)
              .groupIdsSupplier(() -> lazyGroupIds)
              .roleIdsSupplier(() -> lazyRoleIds)
              .tenantsSupplier(() -> lazyTenantIds)
              .claims(snapshotClaims);
        });
  }
}
