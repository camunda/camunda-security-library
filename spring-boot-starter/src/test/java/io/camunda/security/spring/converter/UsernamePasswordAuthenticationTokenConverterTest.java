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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.auth.MembershipProvider;
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
  @Mock private MembershipProvider provider;
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
    when(membershipPort.createProviderForUser(eq("alice"))).thenReturn(provider);
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void wiresGroupsRolesTenantsFromProvider() {
    when(membershipPort.createProviderForUser(eq("alice"))).thenReturn(provider);
    when(provider.groupIds()).thenReturn(List.of("g1", "g2"));
    when(provider.roleIds()).thenReturn(List.of("r1"));
    when(provider.tenantIds()).thenReturn(List.of("t1"));

    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    assertThat(auth.authenticatedGroupIds()).containsExactlyInAnyOrder("g1", "g2");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
  }

  @Test
  void mappingRulesSupplierNotWiredForBasicAuth() {
    when(membershipPort.createProviderForUser(eq("alice"))).thenReturn(provider);

    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));

    // BASIC has no claims; converter intentionally does not wire mappingRulesSupplier. Reading
    // the resulting field must return the record's default empty list *without* going through
    // the provider — otherwise an accidentally-wired supplier would also produce an empty list
    // (Mockito's null return is normalised to empty by LazyList) and the omission would be
    // silently broken.
    assertThat(auth.authenticatedMappingRuleIds()).isEmpty();
    verify(provider, never()).mappingRuleIds();
  }

  @Test
  void claimsAreEmpty() {
    when(membershipPort.createProviderForUser(eq("alice"))).thenReturn(provider);
    final var auth = converter.convert(new UsernamePasswordAuthenticationToken("alice", "pw"));
    assertThat(auth.claims()).isEmpty();
  }
}
