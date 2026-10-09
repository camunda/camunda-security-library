/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.api.model.authz.RoleMembership;
import io.camunda.security.api.model.authz.ScopedRoleMembership;
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
  void resolvePortMethodConvertsClaimsToAuthentication() {
    // given
    final io.camunda.security.api.context.TokenClaimsAuthenticationResolver resolver = converter;
    final var claims = Map.<String, Object>of("sub", "alice");

    // when
    final var auth = resolver.resolve(claims);

    // then
    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.claims()).isEqualTo(claims);
  }

  @Test
  void portIsNotInvokedUntilFieldIsRead() {
    converter.convert(Map.of("sub", "alice"));

    verify(membershipPort, never()).mappingRuleIds(any());
    verify(membershipPort, never()).groupIds(any());
    verify(membershipPort, never()).roleIds(any());
    verify(membershipPort, never()).tenantIds(any());
    verify(membershipPort, never()).scopedRoleMemberships(any());
    verify(membershipPort, never()).roleMemberships(any());
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
    // tenants, scoped role memberships, role memberships)
    assertThat(decorateCalls.get()).isEqualTo(6);
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
  void rejectsEntraV1TokenFromStsWindowsNet() {
    // given - a v1.0 access token from sts.windows.net (api.requestedAccessTokenVersion not set)
    final var claims =
        Map.<String, Object>of(
            "sub", "alice",
            "iss", "https://sts.windows.net/tenant-id/",
            "ver", "1.0");

    assertThatThrownBy(() -> converter.convert(claims))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("v2.0 is required");
  }

  @Test
  void rejectsEntraV1TokenFromLoginMicrosoftonlineCom() {
    // given - an ID token from the v1.0 authority (issuer does not end in /v2.0)
    final var claims =
        Map.<String, Object>of(
            "sub", "alice",
            "iss", "https://login.microsoftonline.com/tenant-id/",
            "ver", "1.0");

    assertThatThrownBy(() -> converter.convert(claims))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("v2.0 is required");
  }

  @Test
  void acceptsEntraV2TokenFromLoginMicrosoftonlineCom() {
    // given - a valid v2.0 token from login.microsoftonline.com
    final var claims =
        Map.<String, Object>of(
            "sub", "alice",
            "iss", "https://login.microsoftonline.com/tenant-id/v2.0",
            "ver", "2.0");

    assertThatNoException().isThrownBy(() -> converter.convert(claims));
  }

  @Test
  void nonMicrosoftIssuerIsUnaffectedByEntraGuard() {
    // given - a token from a non-Microsoft issuer with no ver claim
    final var claims =
        Map.<String, Object>of("sub", "alice", "iss", "https://keycloak.example.com/realms/main");

    assertThatNoException().isThrownBy(() -> converter.convert(claims));
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

  @Test
  void scopedRoleMembershipsAreResolvedLazilyWithTheQueryOfTheRoleLookup() {
    final var claims = Map.<String, Object>of("sub", "alice");
    when(membershipPort.mappingRuleIds(any())).thenReturn(List.of("mr1"));
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));
    when(membershipPort.scopedRoleMemberships(any()))
        .thenAnswer(
            inv -> {
              final MembershipQuery q = inv.getArgument(0);
              assertThat(q.principalId()).isEqualTo("alice");
              assertThat(q.principalType()).isEqualTo(MembershipPort.PrincipalType.USER);
              assertThat(q.resolvedMappingRuleIds()).containsExactly("mr1");
              assertThat(q.resolvedGroupIds()).containsExactly("g1");
              return List.of(new ScopedRoleMembership("editor", "w1"));
            });

    final var auth = converter.convert(claims);
    verify(membershipPort, never()).scopedRoleMemberships(any());

    assertThat(auth.scopedRoleMemberships())
        .containsExactly(new ScopedRoleMembership("editor", "w1"));
    assertThat(auth.scopedRoleMemberships()).hasSize(1);
    verify(membershipPort, times(1)).scopedRoleMemberships(any());
  }

  @Test
  void scopedRoleMembershipsDefaultToEmptyForPortsWithoutScopedMemberships() {
    final MembershipPort plainPort =
        new MembershipPort() {
          @Override
          public List<String> mappingRuleIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> groupIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> roleIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> tenantIds(final MembershipQuery query) {
            return List.of();
          }
        };

    final var auth =
        new LazyTokenClaimsConverter("sub", "azp", true, plainPort).convert(Map.of("sub", "alice"));

    assertThat(auth.scopedRoleMemberships()).isEmpty();
  }

  @Test
  void bindsPropagatedContextAroundDeferredScopedRoleMembershipLookup() {
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
    when(membershipPort.scopedRoleMemberships(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.set(boundContext.get());
              return List.of(new ScopedRoleMembership("editor", "w1"));
            });
    final var auth =
        new LazyTokenClaimsConverter("sub", "azp", true, membershipPort, propagator)
            .convert(Map.of("sub", "alice"));

    assertThat(auth.scopedRoleMemberships())
        .containsExactly(new ScopedRoleMembership("editor", "w1"));

    assertThat(observedDuringLookup.get()).isEqualTo("bound");
    assertThat(boundContext.get()).isNull();
  }

  @Test
  void roleMembershipsAreResolvedLazilyWithTheQueryOfTheRoleLookup() {
    final var claims = Map.<String, Object>of("sub", "alice");
    when(membershipPort.mappingRuleIds(any())).thenReturn(List.of("mr1"));
    when(membershipPort.groupIds(any())).thenReturn(List.of("g1"));
    when(membershipPort.roleMemberships(any()))
        .thenAnswer(
            inv -> {
              final MembershipQuery q = inv.getArgument(0);
              assertThat(q.principalId()).isEqualTo("alice");
              assertThat(q.principalType()).isEqualTo(MembershipPort.PrincipalType.USER);
              assertThat(q.resolvedMappingRuleIds()).containsExactly("mr1");
              assertThat(q.resolvedGroupIds()).containsExactly("g1");
              return List.of(new RoleMembership("editor", List.of()));
            });

    final var auth = converter.convert(claims);
    verify(membershipPort, never()).roleMemberships(any());

    assertThat(auth.roleMemberships()).containsExactly(new RoleMembership("editor", List.of()));
    assertThat(auth.roleMemberships()).hasSize(1);
    verify(membershipPort, times(1)).roleMemberships(any());
  }

  @Test
  void roleMembershipsDefaultToEmptyForPortsWithoutConditionalMemberships() {
    final MembershipPort plainPort =
        new MembershipPort() {
          @Override
          public List<String> mappingRuleIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> groupIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> roleIds(final MembershipQuery query) {
            return List.of();
          }

          @Override
          public List<String> tenantIds(final MembershipQuery query) {
            return List.of();
          }
        };

    final var auth =
        new LazyTokenClaimsConverter("sub", "azp", true, plainPort).convert(Map.of("sub", "alice"));

    assertThat(auth.roleMemberships()).isEmpty();
  }

  @Test
  void bindsPropagatedContextAroundDeferredRoleMembershipLookup() {
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
    when(membershipPort.roleMemberships(any()))
        .thenAnswer(
            invocation -> {
              observedDuringLookup.set(boundContext.get());
              return List.of(new RoleMembership("editor", List.of()));
            });
    final var auth =
        new LazyTokenClaimsConverter("sub", "azp", true, membershipPort, propagator)
            .convert(Map.of("sub", "alice"));

    assertThat(auth.roleMemberships()).containsExactly(new RoleMembership("editor", List.of()));

    assertThat(observedDuringLookup.get()).isEqualTo("bound");
    assertThat(boundContext.get()).isNull();
  }
}
