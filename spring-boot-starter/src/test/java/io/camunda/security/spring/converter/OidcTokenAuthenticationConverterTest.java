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
import io.camunda.security.spring.oidc.NoopOidcClaimsProvider;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class OidcTokenAuthenticationConverterTest {

  @Test
  void supportsJwtAuthenticationToken() {
    final var converter =
        new OidcTokenAuthenticationConverter(
            mock(TokenClaimsConverter.class), new NoopOidcClaimsProvider());
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2AuthenticationToken() {
    final var converter =
        new OidcTokenAuthenticationConverter(
            mock(TokenClaimsConverter.class), new NoopOidcClaimsProvider());
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void passesJwtClaimsThroughNoopProviderToConverter() {
    final TokenClaimsConverter tokenClaimsConverter = mock(TokenClaimsConverter.class);
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(jwt.getClaims())).thenReturn(expected);

    final var converter =
        new OidcTokenAuthenticationConverter(tokenClaimsConverter, new NoopOidcClaimsProvider());
    assertThat(converter.convert(authentication)).isSameAs(expected);
  }

  @Test
  void usesClaimsFromProviderForConversion() {
    final TokenClaimsConverter tokenClaimsConverter = mock(TokenClaimsConverter.class);
    final OidcClaimsProvider claimsProvider = mock(OidcClaimsProvider.class);
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt);
    final Map<String, Object> augmented = Map.of("sub", "alice", "groups", List.of("eng"));
    when(claimsProvider.claimsFor(any(), eq("token"))).thenReturn(augmented);
    final var expected = CamundaAuthentication.of(b -> b.user("alice"));
    when(tokenClaimsConverter.convert(augmented)).thenReturn(expected);

    final var converter =
        new OidcTokenAuthenticationConverter(tokenClaimsConverter, claimsProvider);
    assertThat(converter.convert(authentication)).isSameAs(expected);
  }
}
