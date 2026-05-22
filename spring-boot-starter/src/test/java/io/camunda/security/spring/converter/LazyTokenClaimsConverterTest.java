/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.auth.MembershipPort;
import io.camunda.security.api.model.auth.MembershipQuery;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@ExtendWith(MockitoExtension.class)
class LazyTokenClaimsConverterTest {

  @Mock private MembershipPort membershipPort;
  private OidcConfiguration oidcConfig;

  @BeforeEach
  void setUp() {
    oidcConfig = new OidcConfiguration();
    oidcConfig.setUsernameClaim("sub");
    oidcConfig.setClientIdClaim("azp");
  }

  @Test
  void convertsUserPrincipalFromClaims() {
    final var claims = Map.<String, Object>of("sub", "alice", "azp", "client1");
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));
    when(membershipPort.roleIds(any())).thenReturn(List.of("r1"));
    when(membershipPort.tenantIds(any())).thenReturn(List.of("t1"));
    oidcConfig.setPreferUsernameClaim(true);

    final var auth = new LazyTokenClaimsConverter(oidcConfig, membershipPort).convert(claims);

    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
    assertThat(auth.claims()).isEqualTo(claims);
  }

  @Test
  void portIsNotInvokedUntilFieldIsRead() {
    final var claims = Map.<String, Object>of("sub", "alice");

    new LazyTokenClaimsConverter(oidcConfig, membershipPort).convert(claims);

    // constructing the authentication must not trigger any port calls
    verify(membershipPort, never()).mappingRuleIds(any());
    verify(membershipPort, never()).groupIds(any());
    verify(membershipPort, never()).roleIds(any());
    verify(membershipPort, never()).tenantIds(any());
  }

  @Test
  void convertsClientPrincipalWhenNoUsername() {
    oidcConfig.setUsernameClaim(null);
    final var claims = Map.<String, Object>of("azp", "service-client");
    when(membershipPort.groupIds(any())).thenReturn(List.of());

    final var auth = new LazyTokenClaimsConverter(oidcConfig, membershipPort).convert(claims);

    assertThat(auth.authenticatedGroupIds()).isEmpty(); // iterating triggers lazy resolution
    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
  }

  @Test
  void throwsWhenNeitherClaimPresent() {
    assertThatThrownBy(
            () ->
                new LazyTokenClaimsConverter(oidcConfig, membershipPort).convert(Map.of("x", "y")))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }

  @Test
  void groupsQueryReceivesResolvedMappingRuleIdsFromChain() {
    // groupIds() is called with a query whose resolvedMappingRuleIds is already populated
    // by the upstream LazyList reference resolving first.
    final var claims = Map.<String, Object>of("sub", "alice");
    when(membershipPort.mappingRuleIds(any())).thenReturn(List.of("mr1"));
    when(membershipPort.groupIds(any()))
        .thenAnswer(
            inv -> {
              final MembershipQuery q = inv.getArgument(0);
              assertThat(q.resolvedMappingRuleIds()).containsExactly("mr1");
              return List.of("g1");
            });
    final var auth = new LazyTokenClaimsConverter(oidcConfig, membershipPort).convert(claims);

    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
  }
}
