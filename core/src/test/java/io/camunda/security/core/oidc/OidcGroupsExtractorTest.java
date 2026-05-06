/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OidcGroupsExtractorTest {

  @Test
  void shouldReturnNullWhenGroupsClaimNotConfigured() {
    final OidcGroupsExtractor extractor = new OidcGroupsExtractor(null);

    assertThat(extractor.extract(Map.of("groups", List.of("a")))).isNull();
  }

  @Test
  void shouldExtractStringGroupFromClaims() {
    final OidcGroupsExtractor extractor = new OidcGroupsExtractor("groups");

    assertThat(extractor.extract(Map.of("groups", "engineering"))).containsExactly("engineering");
  }

  @Test
  void shouldExtractGroupListFromClaims() {
    final OidcGroupsExtractor extractor = new OidcGroupsExtractor("groups");

    assertThat(extractor.extract(Map.of("groups", List.of("a", "b")))).containsExactly("a", "b");
  }

  @Test
  void shouldReturnEmptyListWhenPathNotFound() {
    final OidcGroupsExtractor extractor = new OidcGroupsExtractor("groups");

    assertThat(extractor.extract(Map.of("other", "value"))).isEmpty();
  }

  @Test
  void shouldThrowWhenDerivedListContainsNonStringValues() {
    final OidcGroupsExtractor extractor = new OidcGroupsExtractor("groups");

    assertThatThrownBy(() -> extractor.extract(Map.of("groups", List.of("a", 7))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("not a string array");
  }
}
