/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.auth.Groups;
import io.camunda.security.api.model.auth.MappingRules;
import io.camunda.security.api.model.auth.Memberships;
import io.camunda.security.api.model.auth.Roles;
import io.camunda.security.api.model.auth.Tenants;
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
class UsernamePasswordAuthenticationTokenConverterTest {

  @Mock private MembershipPort membershipPort;
  @InjectMocks private UsernamePasswordAuthenticationTokenConverter converter;

  @Test
  void supportsUsernamePasswordToken() {
    assertThat(converter.supports(new UsernamePasswordAuthenticationToken("u", "p"))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2Token() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void setsUsernameOnAuthentication() {
    when(membershipPort.resolveMembershipsForUser(eq("alice"))).thenReturn(Memberships.empty());
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void setsGroupsRolesTenantsFromMemberships() {
    final var memberships =
        new Memberships(
            new Groups(List.of("g1", "g2")),
            new Roles(List.of("r1")),
            new Tenants(List.of("t1")),
            new MappingRules(List.of()));
    when(membershipPort.resolveMembershipsForUser(eq("alice"))).thenReturn(memberships);

    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    assertThat(auth.authenticatedGroupIds()).containsExactlyInAnyOrder("g1", "g2");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
  }

  @Test
  void claimsAreEmpty() {
    when(membershipPort.resolveMembershipsForUser(eq("alice"))).thenReturn(Memberships.empty());
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.claims()).isEmpty();
  }
}
