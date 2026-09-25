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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class AdditionalJwkSetUrisByRegistrationIdTest {

  private static final String JWKS = "https://secondary.example.com/jwks";

  @Test
  void returnsTheUrisOfAKnownRegistration() {
    final var lookup = new AdditionalJwkSetUrisByRegistrationId(Map.of("oidc", List.of(JWKS)));

    assertThat(lookup.get("oidc")).containsExactly(JWKS);
  }

  @Test
  void returnsNullForAnUnknownOrAbsentRegistrationId() {
    final var lookup = new AdditionalJwkSetUrisByRegistrationId(Map.of("oidc", List.of(JWKS)));

    assertThat(lookup.get("entra")).isNull();
    assertThat(lookup.get(null)).isNull();
  }

  @Test
  void treatsANullMapAsEmpty() {
    final var lookup = new AdditionalJwkSetUrisByRegistrationId(null);

    assertThat(lookup.byRegistrationId()).isEmpty();
    assertThat(lookup.get("oidc")).isNull();
  }

  @Test
  void emptyLookupResolvesNothing() {
    assertThat(AdditionalJwkSetUrisByRegistrationId.empty().get("oidc")).isNull();
  }

  @Test
  void copiesTheSuppliedMapAndItsLists() {
    final var uris = new ArrayList<>(List.of(JWKS));
    final Map<String, List<String>> source = new LinkedHashMap<>();
    source.put("oidc", uris);
    final var lookup = new AdditionalJwkSetUrisByRegistrationId(source);

    source.put("entra", List.of("https://entra.example.com/jwks"));
    uris.clear();

    assertThat(lookup.byRegistrationId()).containsExactly(Map.entry("oidc", List.of(JWKS)));
    assertThatThrownBy(() -> lookup.byRegistrationId().put("host", List.of(JWKS)))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
