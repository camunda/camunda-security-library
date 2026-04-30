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

import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationTest {

  @Test
  void webAppAccessProducesAccessOnComponent() {
    final var auth = Authorization.webAppAccess("operate");

    assertThat(auth.permissionType()).isEqualTo("ACCESS");
    assertThat(auth.resourceType()).isEqualTo("COMPONENT");
    assertThat(auth.resourceIds()).containsExactly("operate");
    assertThat(auth.resourcePropertyNames()).isEmpty();
  }

  @Test
  void webAppAccessRejectsNullWebApp() {
    assertThatThrownBy(() -> Authorization.webAppAccess(null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void resourceIdsAreImmutableAfterConstruction() {
    final var mutable = new java.util.HashSet<>(Set.of("a", "b"));
    final var auth = new Authorization<>("READ", "FOO", mutable, Set.of());

    mutable.add("c");

    assertThat(auth.resourceIds()).containsExactlyInAnyOrder("a", "b");
  }

  @Test
  void nullCollectionsBecomeEmpty() {
    final var auth = new Authorization<>("READ", "FOO", null, null);

    assertThat(auth.resourceIds()).isEmpty();
    assertThat(auth.resourcePropertyNames()).isEmpty();
  }
}
