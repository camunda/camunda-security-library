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

import io.camunda.security.core.port.out.MembershipPort;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

@ExtendWith(MockitoExtension.class)
class LazyUsernamePasswordAuthenticationTokenConverterTest {

  @Mock private MembershipPort membershipPort;
  @InjectMocks private LazyUsernamePasswordAuthenticationTokenConverter converter;

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
}
