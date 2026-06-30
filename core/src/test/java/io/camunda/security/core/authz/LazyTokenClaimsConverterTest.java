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

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipQuery;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LazyTokenClaimsConverterTest {

  @Mock private MembershipPort membershipPort;
  private LazyTokenClaimsConverter converter;

  @BeforeEach
  void setUp() {
    converter = new LazyTokenClaimsConverter("sub", "azp", true, membershipPort);
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
    final var noUsernameConverter = new LazyTokenClaimsConverter(null, "azp", true, membershipPort);
    final var claims = Map.<String, Object>of("azp", "service-client");
    when(membershipPort.groupIds(any())).thenReturn(List.of());

    final var auth = noUsernameConverter.convert(claims);

    assertThat(auth.authenticatedGroupIds()).isEmpty(); // triggers lazy resolution
    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
  }

  @Test
  void preferClientIdWhenFlagFalse() {
    final var preferClientConverter =
        new LazyTokenClaimsConverter("sub", "azp", false, membershipPort);
    final var claims = Map.<String, Object>of("sub", "alice", "azp", "service-client");

    final var auth = preferClientConverter.convert(claims);

    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
    assertThat(auth.authenticatedUsername()).isNull();
  }

  @Test
  void throwsIllegalArgumentExceptionWhenNeitherClaimPresent() {
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
  void capturesContextAtConstructionForEachMembershipSupplier() {
    // given a propagator that records how many suppliers it decorates
    final AtomicInteger decorateCalls = new AtomicInteger();
    final MembershipResolutionContextPropagator propagator =
        supplier -> {
          decorateCalls.incrementAndGet();
          return supplier;
        };
    final var capturingConverter =
        new LazyTokenClaimsConverter("sub", "azp", true, membershipPort, propagator);

    // when the authentication is built (before any membership field is read)
    capturingConverter.convert(Map.of("sub", "alice"));

    // then the propagator was applied once per membership supplier (mapping rules, groups, roles,
    // tenants)
    assertThat(decorateCalls.get()).isEqualTo(4);
  }

  @Test
  void bindsPropagatedContextAroundDeferredMembershipLookup() {
    // given a propagator that binds a marker for the duration of the deferred lookup
    final AtomicReference<String> boundContext = new AtomicReference<>();
    final MembershipResolutionContextPropagator propagator =
        supplier ->
            () -> {
              boundContext.set("bound");
              try {
                return supplier.get();
              } finally {
                boundContext.set(null);
              }
            };
    final AtomicReference<String> observedDuringLookup = new AtomicReference<>();
    when(membershipPort.groupIds(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.set(boundContext.get());
              return List.of("g1");
            });
    final var capturingConverter =
        new LazyTokenClaimsConverter("sub", "azp", true, membershipPort, propagator);
    final var auth = capturingConverter.convert(Map.of("sub", "alice"));

    // when the lazy group list is materialised
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");

    // then the host context was bound while the membership lookup ran, and cleared afterwards
    assertThat(observedDuringLookup.get()).isEqualTo("bound");
    assertThat(boundContext.get()).isNull();
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
