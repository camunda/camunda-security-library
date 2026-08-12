/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.core.port.out.MembershipPort;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

@ExtendWith(MockitoExtension.class)
class LazyUsernamePasswordAuthenticationTokenConverterTest {

  @Mock private MembershipPort membershipPort;
  private LazyUsernamePasswordAuthenticationTokenConverter converter;

  @BeforeEach
  void setUp() {
    converter = new LazyUsernamePasswordAuthenticationTokenConverter(membershipPort);
  }

  @Test
  void supportsUsernamePasswordToken() {
    assertThat(converter.supports(new UsernamePasswordAuthenticationToken("u", "p"))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2Token() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void portIsNotInvokedUntilFieldIsRead() {
    converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    verify(membershipPort, never()).groupIds(any());
    verify(membershipPort, never()).roleIds(any());
    verify(membershipPort, never()).tenantIds(any());
  }

  @Test
  void wiresGroupsRolesTenantsFromPort() {
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1", "g2"));
    when(membershipPort.roleIds(any())).thenReturn(List.of("r1"));
    when(membershipPort.tenantIds(any())).thenReturn(List.of("t1"));

    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    assertThat(auth.authenticatedGroupIds()).containsExactlyInAnyOrder("g1", "g2");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void mappingRulesSupplierNotWiredForBasicAuth() {
    // mappingRulesSupplier is deliberately not wired — the record default (empty list) is
    // returned without calling port.mappingRuleIds().
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.authenticatedMappingRuleIds()).isEmpty();
    verify(membershipPort, never()).mappingRuleIds(any());
  }

  @Test
  void claimsAreEmpty() {
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.claims()).isEmpty();
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
        new LazyUsernamePasswordAuthenticationTokenConverter(membershipPort, propagator);

    // when the authentication is built (before any membership field is read)
    capturingConverter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    // then the propagator was applied once per membership supplier (groups, roles, tenants —
    // no mappingRuleIds for BASIC auth)
    assertThat(decorateCalls.get()).isEqualTo(3);
  }

  @Test
  void bindsPropagatedContextAroundDeferredMembershipLookup() {
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
        new LazyUsernamePasswordAuthenticationTokenConverter(membershipPort, propagator);
    final var auth =
        capturingConverter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    // when the lazy group list is materialised
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");

    // then the host context was bound while the membership lookup ran, and cleared afterwards
    assertThat(observedDuringLookup.get()).isEqualTo("bound");
    assertThat(boundContext.get()).isNull();
  }
}
