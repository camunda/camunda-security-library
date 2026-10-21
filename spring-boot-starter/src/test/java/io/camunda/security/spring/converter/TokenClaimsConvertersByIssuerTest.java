/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TokenClaimsConvertersByIssuerTest {

  @Test
  void returnsConverterForMatchingIssuer() {
    final var entraConverter = mock(LazyTokenClaimsConverter.class);
    final var defaultConverter = mock(LazyTokenClaimsConverter.class);
    final var converters =
        new TokenClaimsConvertersByIssuer(Map.of("https://entra.example.com", entraConverter));

    assertThat(converters.getOrDefault("https://entra.example.com", defaultConverter))
        .isSameAs(entraConverter);
  }

  @Test
  void returnsDefaultConverterWhenIssuerDoesNotMatchAnyEntry() {
    final var entraConverter = mock(LazyTokenClaimsConverter.class);
    final var defaultConverter = mock(LazyTokenClaimsConverter.class);
    final var converters =
        new TokenClaimsConvertersByIssuer(Map.of("https://entra.example.com", entraConverter));

    assertThat(converters.getOrDefault("https://auth0.example.com", defaultConverter))
        .isSameAs(defaultConverter);
  }

  /**
   * The configured issuer-uri can carry a trailing slash the provider's tokens don't, see
   * camunda/camunda#61896. Its converter must still apply, not the default one.
   */
  @Test
  void returnsConverterForAnIssuerThatDiffersOnlyByATrailingSlash() {
    final var entraConverter = mock(LazyTokenClaimsConverter.class);
    final var defaultConverter = mock(LazyTokenClaimsConverter.class);
    final var converters =
        new TokenClaimsConvertersByIssuer(
            Map.of("https://login.microsoftonline.com/tenant/v2.0/", entraConverter));

    assertThat(
            converters.getOrDefault(
                "https://login.microsoftonline.com/tenant/v2.0", defaultConverter))
        .isSameAs(entraConverter);
  }

  @Test
  void returnsDefaultConverterWhenIssuerIsNull() {
    final var entraConverter = mock(LazyTokenClaimsConverter.class);
    final var defaultConverter = mock(LazyTokenClaimsConverter.class);
    final var converters =
        new TokenClaimsConvertersByIssuer(Map.of("https://entra.example.com", entraConverter));

    assertThat(converters.getOrDefault(null, defaultConverter)).isSameAs(defaultConverter);
  }

  @Test
  void treatsNullMapAsEmpty() {
    final var defaultConverter = mock(LazyTokenClaimsConverter.class);
    final var converters = new TokenClaimsConvertersByIssuer(null);

    assertThat(converters.getOrDefault("https://entra.example.com", defaultConverter))
        .isSameAs(defaultConverter);
    assertThat(converters.byIssuer()).isEmpty();
  }
}
