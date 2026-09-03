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

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class JwtGrantedAuthoritiesAuthenticationConverterTest {

  private final JwtGrantedAuthoritiesAuthenticationConverter converter =
      new JwtGrantedAuthoritiesAuthenticationConverter();

  @Test
  void supportsJwtAuthenticationToken() {
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    assertThat(converter.supports(new JwtAuthenticationToken(jwt, List.of()))).isTrue();
  }

  @Test
  void doesNotSupportNonJwtAuthentication() {
    assertThat(converter.supports(new UsernamePasswordAuthenticationToken("user", "password")))
        .isFalse();
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

  @Test
  void throwsOAuth2AuthenticationExceptionWhenSubjectBlank() {
    final var jwt = Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "  ").build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    assertThatThrownBy(() -> converter.convert(authentication))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN));
  }

  @Test
  void usesConfiguredUsernameClaimWhenPresent() {
    final var customClaimConverter =
        new JwtGrantedAuthoritiesAuthenticationConverter("employee_id");
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("sub", "0607abf4-e5c6-430d-8624-32b205dad6c1")
            .claim("employee_id", "alice")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = customClaimConverter.convert(authentication);

    assertThat(result.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void fallsBackToSubjectWhenConfiguredClaimMissing() {
    final var customClaimConverter =
        new JwtGrantedAuthoritiesAuthenticationConverter("employee_id");
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("sub", "0607abf4-e5c6-430d-8624-32b205dad6c1")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = customClaimConverter.convert(authentication);

    assertThat(result.authenticatedUsername()).isEqualTo("0607abf4-e5c6-430d-8624-32b205dad6c1");
  }

  @Test
  void fallsBackToSubjectWhenConfiguredClaimBlank() {
    final var customClaimConverter =
        new JwtGrantedAuthoritiesAuthenticationConverter("employee_id");
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("sub", "0607abf4-e5c6-430d-8624-32b205dad6c1")
            .claim("employee_id", "  ")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = customClaimConverter.convert(authentication);

    assertThat(result.authenticatedUsername()).isEqualTo("0607abf4-e5c6-430d-8624-32b205dad6c1");
  }

  @Test
  void noArgConstructorStillDefaultsToSubjectClaim() {
    final var defaultConverter = new JwtGrantedAuthoritiesAuthenticationConverter();
    final var jwt =
        Jwt.withTokenValue("token").header("alg", "RS256").claim("sub", "alice").build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    final var result = defaultConverter.convert(authentication);

    assertThat(result.authenticatedUsername()).isEqualTo("alice");
  }

  @Test
  void throwsOAuth2AuthenticationExceptionWhenConfiguredClaimAndSubjectBothMissing() {
    final var customClaimConverter =
        new JwtGrantedAuthoritiesAuthenticationConverter("employee_id");
    final var jwt =
        Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .claim("iss", "https://issuer.example")
            .build();
    final var authentication = new JwtAuthenticationToken(jwt, List.of());

    assertThatThrownBy(() -> customClaimConverter.convert(authentication))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            ex -> {
              assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_TOKEN);
              assertThat(ex.getError().getDescription()).contains("employee_id");
            });
  }
}
