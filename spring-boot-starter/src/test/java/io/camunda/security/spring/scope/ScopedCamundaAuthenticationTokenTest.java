/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

class ScopedCamundaAuthenticationTokenTest {

  private static final Jwt JWT =
      Jwt.withTokenValue("token-value").header("alg", "RS256").claim("sub", "s").build();

  @Test
  void carriesTheJwtAndCamundaAuthenticationAndIsAuthenticated() {
    final var camunda = CamundaAuthentication.of(b -> b.user("dave"));

    final var token = new ScopedCamundaAuthenticationToken(JWT, camunda);

    assertThat(token.getToken()).isSameAs(JWT);
    assertThat(token.getCamundaAuthentication()).isSameAs(camunda);
    assertThat(token.isAuthenticated()).isTrue();
    assertThat(token.getCredentials()).isEqualTo("token-value");
    assertThat(token.getPrincipal()).isSameAs(JWT);
    assertThat(token.getAuthorities()).isEmpty();
  }

  @Test
  void nameIsTheUsernameWhenPresentOtherwiseTheClientId() {
    assertThat(
            new ScopedCamundaAuthenticationToken(JWT, CamundaAuthentication.of(b -> b.user("dave")))
                .getName())
        .isEqualTo("dave");
    assertThat(
            new ScopedCamundaAuthenticationToken(
                    JWT, CamundaAuthentication.of(b -> b.clientId("client-1")))
                .getName())
        .isEqualTo("client-1");
  }

  @Test
  void carriesSuppliedAuthorities() {
    final var token =
        new ScopedCamundaAuthenticationToken(
            JWT,
            CamundaAuthentication.of(b -> b.user("dave")),
            List.of(new SimpleGrantedAuthority("ROLE_X")));

    assertThat(token.getAuthorities()).extracting("authority").containsExactly("ROLE_X");
  }

  @Test
  void rejectsNullJwtOrCamundaAuthentication() {
    assertThatThrownBy(
            () ->
                new ScopedCamundaAuthenticationToken(
                    null, CamundaAuthentication.of(b -> b.user("d"))))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> new ScopedCamundaAuthenticationToken(JWT, null))
        .isInstanceOf(NullPointerException.class);
  }
}
