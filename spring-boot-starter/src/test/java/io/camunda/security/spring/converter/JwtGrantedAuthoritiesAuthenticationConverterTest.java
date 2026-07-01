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
import static org.mockito.Mockito.mock;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class JwtGrantedAuthoritiesAuthenticationConverterTest {

  private final JwtGrantedAuthoritiesAuthenticationConverter converter =
      new JwtGrantedAuthoritiesAuthenticationConverter();

  @Test
  void supportsJwtAuthenticationToken() {
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isTrue();
  }

  @Test
  void doesNotSupportOAuth2AuthenticationToken() {
    assertThat(converter.supports(mock(OAuth2AuthenticationToken.class))).isFalse();
  }

  @Test
  void mapsSubjectToAuthenticatedUsername() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = converter.convert(authentication);

    assertThat(result.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void mapsGrantedAuthoritiesToRoleIds() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication =
        new JwtAuthenticationToken(
            jwt, List.of(new SimpleGrantedAuthority("read"), new SimpleGrantedAuthority("write")));

    final var result = converter.convert(authentication);

    assertThat(result.authenticatedRoleIds()).containsExactlyInAnyOrder("read", "write");
  }

  @Test
  void producesEmptyRoleIdsWhenTokenHasNoAuthorities() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = converter.convert(authentication);

    assertThat(result.authenticatedRoleIds()).isEmpty();
  }

  @Test
  void copiesAllJwtClaimsToAuthentication() {
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("sub", "alice")
            .claim("https://camunda.com/orgs", List.of(Map.of("id", "org-1")))
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = converter.convert(authentication);

    assertThat(result.claims()).containsAllEntriesOf(jwt.getClaims());
  }

  @Test
  void throwsOAuth2AuthenticationExceptionWhenSubjectMissing() {
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://issuer.example")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    assertThatThrownBy(() -> converter.convert(authentication))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }
}
