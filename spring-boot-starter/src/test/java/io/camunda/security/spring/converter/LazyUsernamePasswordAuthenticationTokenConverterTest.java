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
  void decoratesEachMembershipSupplierOnce() {
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
    // given a propagator shaped like the real production one: it captures the simulated
    // thread-local at decorate() time (while still on the "request thread"), then
    // rebinds exactly that captured value around the deferred call — regardless of what the
    // thread-local looks like by the time the call actually happens.
    final AtomicReference<String> simulatedThreadLocal = new AtomicReference<>("tenant-x");
    final MembershipResolutionContextPropagator propagator =
        supplier -> {
          final String captured = simulatedThreadLocal.get();
          return () -> {
            final String previous = simulatedThreadLocal.get();
            simulatedThreadLocal.set(captured);
            try {
              return supplier.get();
            } finally {
              simulatedThreadLocal.set(previous);
            }
          };
        };
    final Map<String, String> observedDuringLookup = new HashMap<>();
    when(membershipPort.groupIds(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.put("groupIds", simulatedThreadLocal.get());
              return List.of("g1");
            });
    when(membershipPort.roleIds(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.put("roleIds", simulatedThreadLocal.get());
              return List.of("r1");
            });
    when(membershipPort.tenantIds(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.put("tenantIds", simulatedThreadLocal.get());
              return List.of("t1");
            });

    final var capturingConverter =
        new LazyUsernamePasswordAuthenticationTokenConverter(membershipPort, propagator);
    // when the authentication is built (decorate() fires here, capturing "tenant-x")
    final var auth =
        capturingConverter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    // simulate request/thread teardown: the thread-local is gone by the time the lazy fields are
    // actually read
    simulatedThreadLocal.set(null);

    // when the lazy fields are materialised, long after teardown
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");

    // then each lookup observed the context captured at construction time, not the (absent)
    // thread-local at the time it actually ran
    assertThat(observedDuringLookup)
        .containsEntry("groupIds", "tenant-x")
        .containsEntry("roleIds", "tenant-x")
        .containsEntry("tenantIds", "tenant-x");
    // and the thread-local was correctly restored to its pre-lookup state (null) afterward
    assertThat(simulatedThreadLocal.get()).isNull();
  }

  @Test
  void nestedGroupLookupDuringRoleResolutionPreservesOuterBoundContext() {
    // given a propagator shaped like the real production one
    // (PhysicalTenantContext.propagateCurrent):
    // it saves and restores the previously-bound value, rather than unconditionally clearing it.
    final AtomicReference<String> bound = new AtomicReference<>();
    final MembershipResolutionContextPropagator propagator =
        supplier ->
            () -> {
              final String previous = bound.get();
              bound.set("tenant-x");
              try {
                return supplier.get();
              } finally {
                bound.set(previous);
              }
            };
    final AtomicReference<String> observedDuringRoleLookup = new AtomicReference<>();
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));
    // Mirrors DefaultMembershipService.roleIds(), which reads the not-yet-resolved group list
    // synchronously — forcing the independently-decorated groups supplier to resolve from
    // *inside* this call, nested within the roles call's own decorated scope.
    when(membershipPort.roleIds(any()))
        .thenAnswer(
            invocation -> {
              final MembershipQuery query = invocation.getArgument(0);
              final boolean groupsEmpty = query.resolvedGroupIds().isEmpty();
              observedDuringRoleLookup.set(bound.get());
              return groupsEmpty ? List.of() : List.of("r1");
            });
    final var capturingConverter =
        new LazyUsernamePasswordAuthenticationTokenConverter(membershipPort, propagator);
    final var auth =
        capturingConverter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    // when the lazy role list is materialised, forcing the nested group resolution
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");

    // then the outer (roles) binding survived the nested (groups) resolution's cleanup — a
    // save-and-restore propagator does not clobber its own outer scope when re-entered
    assertThat(observedDuringRoleLookup.get()).isEqualTo("tenant-x");
  }
}
