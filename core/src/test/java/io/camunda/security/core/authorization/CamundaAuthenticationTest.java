/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CamundaAuthenticationTest {

  @Test
  void unauthenticatedIsFlaggedAnonymousAndCarriesNoIdentity() {
    final var auth = CamundaAuthentication.unauthenticated();

    assertThat(auth.anonymous()).isTrue();
    assertThat(auth.authenticatedUsername()).isNull();
    assertThat(auth.authenticatedClientId()).isNull();
    assertThat(auth.authenticatedRoleIds()).isEmpty();
    assertThat(auth.authenticatedGroupIds()).isEmpty();
    assertThat(auth.authenticatedMappingRuleIds()).isEmpty();
    assertThat(auth.claims()).isEmpty();
  }

  @Test
  void builderPopulatesAllFields() {
    final var auth =
        CamundaAuthentication.builder()
            .authenticatedUsername("ben")
            .authenticatedRoleIds(Set.of("admin"))
            .authenticatedGroupIds(Set.of("eng"))
            .authenticatedMappingRuleIds(Set.of("github-admins"))
            .claims(Map.of("email", "ben@example.com"))
            .build();

    assertThat(auth.authenticatedUsername()).isEqualTo("ben");
    assertThat(auth.authenticatedRoleIds()).containsExactly("admin");
    assertThat(auth.authenticatedGroupIds()).containsExactly("eng");
    assertThat(auth.authenticatedMappingRuleIds()).containsExactly("github-admins");
    assertThat(auth.claims()).containsEntry("email", "ben@example.com");
    assertThat(auth.anonymous()).isFalse();
  }

  @Test
  void nullCollectionsBecomeEmpty() {
    final var auth = new CamundaAuthentication("u", null, false, null, null, null, null);

    assertThat(auth.authenticatedRoleIds()).isEmpty();
    assertThat(auth.authenticatedGroupIds()).isEmpty();
    assertThat(auth.authenticatedMappingRuleIds()).isEmpty();
    assertThat(auth.claims()).isEmpty();
  }

  @Test
  void recordIsImmutable() {
    final var roles = new java.util.HashSet<>(Set.of("a"));
    final var auth =
        CamundaAuthentication.builder()
            .authenticatedUsername("u")
            .authenticatedRoleIds(roles)
            .build();

    roles.add("b");

    assertThat(auth.authenticatedRoleIds()).containsExactly("a");
  }

  @Test
  void anonymousWithUsernameIsRejected() {
    assertThatThrownBy(() -> new CamundaAuthentication("ben", null, true, null, null, null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Anonymous");
  }

  @Test
  void anonymousWithClientIdIsRejected() {
    assertThatThrownBy(
            () -> new CamundaAuthentication(null, "client", true, null, null, null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Anonymous");
  }

  @Test
  void nonAnonymousWithBothUsernameAndClientIdIsRejected() {
    assertThatThrownBy(
            () -> new CamundaAuthentication("ben", "client", false, null, null, null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("both");
  }
}
