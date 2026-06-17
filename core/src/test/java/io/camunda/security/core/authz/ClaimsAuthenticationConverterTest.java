/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipQuery;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClaimsAuthenticationConverterTest {

  @Mock private MembershipPort membershipPort;
  private ClaimsAuthenticationConverter converter;

  @BeforeEach
  void setUp() {
    converter = new ClaimsAuthenticationConverter("sub", "azp", true, membershipPort);
  }

  @Test
  void convertsUserPrincipalFromClaims() {
    final var claims = Map.<String, Object>of("sub", "alice", "azp", "client1");
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));
    when(membershipPort.roleIds(any())).thenReturn(List.of("r1"));
    when(membershipPort.tenantIds(any())).thenReturn(List.of("t1"));

    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
    assertThat(auth.claims()).isEqualTo(claims);
  }

  @Test
  void portIsNotInvokedUntilFieldIsRead() {
    converter.convert(Map.of("sub", "alice"));

    verify(membershipPort, never()).mappingRuleIds(any());
    verify(membershipPort, never()).groupIds(any());
    verify(membershipPort, never()).roleIds(any());
    verify(membershipPort, never()).tenantIds(any());
  }

  @Test
  void convertsClientPrincipalWhenNoUsername() {
    final var noUsernameConverter =
        new ClaimsAuthenticationConverter(null, "azp", true, membershipPort);
    final var claims = Map.<String, Object>of("azp", "service-client");
    when(membershipPort.groupIds(any())).thenReturn(List.of());

    final var auth = noUsernameConverter.convert(claims);

    assertThat(auth.authenticatedGroupIds()).isEmpty(); // triggers lazy resolution
    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
  }

  @Test
  void preferClientIdWhenFlagFalse() {
    final var preferClientConverter =
        new ClaimsAuthenticationConverter("sub", "azp", false, membershipPort);
    final var claims = Map.<String, Object>of("sub", "alice", "azp", "service-client");

    final var auth = preferClientConverter.convert(claims);

    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
    assertThat(auth.authenticatedUsername()).isNull();
  }

  @Test
  void throwsIllegalArgumentExceptionWhenNeitherClaimPresent() {
    // Unlike LazyTokenClaimsConverter, this converter throws IllegalArgumentException (not Spring)
    assertThatThrownBy(() -> converter.convert(Map.of("x", "y")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("sub")
        .hasMessageContaining("azp");
  }

  @Test
  void convertsClaimsContainingNullValues() {
    final var claims = new HashMap<String, Object>();
    claims.put("sub", "alice");
    claims.put("family_name", null);

    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.claims()).hasSize(1).containsEntry("sub", "alice");
  }

  @Test
  void groupsQueryReceivesResolvedMappingRuleIdsFromChain() {
    final var claims = Map.<String, Object>of("sub", "alice");
    when(membershipPort.mappingRuleIds(any())).thenReturn(List.of("mr1"));
    when(membershipPort.groupIds(any()))
        .thenAnswer(
            inv -> {
              final MembershipQuery q = inv.getArgument(0);
              assertThat(q.resolvedMappingRuleIds()).containsExactly("mr1");
              return List.of("g1");
            });

    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
  }
}
