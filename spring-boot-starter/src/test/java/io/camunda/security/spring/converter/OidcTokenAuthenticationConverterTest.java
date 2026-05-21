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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@ExtendWith(MockitoExtension.class)
class OidcTokenAuthenticationConverterTest {

  @Mock private TokenClaimsConverter tokenClaimsConverter;
  @Mock private OidcClaimsProvider claimsProvider;
  @InjectMocks private OidcTokenAuthenticationConverter converter;

  @Test
  void supportsJwtAuthenticationToken() {
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2AuthenticationToken() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void passesJwtClaimsThroughProviderToConverter() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    when(claimsProvider.claimsFor(jwt.getClaims(), "token")).thenReturn(jwt.getClaims());
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    assertThat(converter.convert(authentication)).isSameAs(expected);
  }

  @Test
  void usesAugmentedClaimsFromProviderForConversion() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final Map<String, Object> augmented = Map.of("sub", "alice", "groups", List.of("eng"));
    when(claimsProvider.claimsFor(any(), eq("token"))).thenReturn(augmented);
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(augmented)).thenReturn(expected);

    assertThat(converter.convert(authentication)).isSameAs(expected);
  }
}
