/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.camunda.security.api.model.CamundaAuthentication;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

class ScopedCamundaAuthenticationConverterTest {

  private final ScopedCamundaAuthenticationConverter converter =
      new ScopedCamundaAuthenticationConverter();

  @Test
  void supportsOnlyTheScopedToken() {
    final var jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "s").build();
    final var scoped =
        new ScopedCamundaAuthenticationToken(jwt, CamundaAuthentication.of(b -> b.user("dave")));

    assertThat(converter.supports(scoped)).isTrue();
    // A plain JwtAuthenticationToken belongs to the host's global converter, not this one.
    assertThat(converter.supports(new JwtAuthenticationToken(jwt))).isFalse();
    assertThat(converter.supports(mock(JwtAuthenticationToken.class))).isFalse();
    assertThat(converter.supports(null)).isFalse();
  }

  @Test
  void returnsTheCarriedCamundaAuthentication() {
    final var jwt = Jwt.withTokenValue("t").header("alg", "RS256").claim("sub", "s").build();
    final var camunda = CamundaAuthentication.of(b -> b.user("dave"));

    assertThat(converter.convert(new ScopedCamundaAuthenticationToken(jwt, camunda)))
        .isSameAs(camunda);
  }
}
