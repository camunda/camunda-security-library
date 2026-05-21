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
import static org.mockito.Mockito.when;

import io.camunda.security.api.model.auth.MembershipProvider;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.core.port.out.MembershipPort.PrincipalType;
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
class TokenClaimsConverterTest {

  @Mock private MembershipPort membershipPort;
  @Mock private MembershipProvider provider;
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
    when(membershipPort.createProvider(claims, "alice", PrincipalType.USER)).thenReturn(provider);
    when(provider.groups()).thenReturn(List.of("g1"));
    when(provider.roles()).thenReturn(List.of("r1"));
    when(provider.tenants()).thenReturn(List.of("t1"));
    oidcConfig.setPreferUsernameClaim(true);

    final var converter = new TokenClaimsConverter(oidcConfig, membershipPort);
    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.authenticatedGroupIds()).containsExactly("g1");
    assertThat(auth.authenticatedRoleIds()).containsExactly("r1");
    assertThat(auth.authenticatedTenantIds()).containsExactly("t1");
    assertThat(auth.claims()).isEqualTo(claims);
  }

  @Test
  void convertsClientPrincipalWhenNoUsername() {
    oidcConfig.setUsernameClaim(null);
    final var claims = Map.<String, Object>of("azp", "service-client");
    when(membershipPort.createProvider(claims, "service-client", PrincipalType.CLIENT))
        .thenReturn(provider);

    final var converter = new TokenClaimsConverter(oidcConfig, membershipPort);
    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedClientId()).isEqualTo("service-client");
  }

  @Test
  void throwsWhenNeitherClaimPresent() {
    final var converter = new TokenClaimsConverter(oidcConfig, membershipPort);
    assertThatThrownBy(() -> converter.convert(Map.of("other", "value")))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode())
                    .as("RFC 6750: missing required claims is invalid_token, not invalid_client")
                    .isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }

  @Test
  void preferUsernameClaimFlagSelectsUser() {
    oidcConfig.setPreferUsernameClaim(true);
    final var claims = Map.<String, Object>of("sub", "alice", "azp", "client1");
    when(membershipPort.createProvider(claims, "alice", PrincipalType.USER)).thenReturn(provider);

    final var converter = new TokenClaimsConverter(oidcConfig, membershipPort);
    final var auth = converter.convert(claims);

    assertThat(auth.authenticatedUsername()).isEqualTo("alice");
    assertThat(auth.authenticatedClientId()).isNull();
  }
}
