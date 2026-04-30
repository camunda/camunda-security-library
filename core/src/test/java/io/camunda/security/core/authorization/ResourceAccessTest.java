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

import io.camunda.security.core.authorization.ResourceAccess.Allowed;
import io.camunda.security.core.authorization.ResourceAccess.Denied;
import io.camunda.security.core.authorization.ResourceAccess.Wildcard;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceAccessTest {

  @Test
  void allowedIsAllowed() {
    assertThat(new Allowed(Set.of("a")).allowed()).isTrue();
  }

  @Test
  void wildcardIsAllowed() {
    assertThat(new Wildcard().allowed()).isTrue();
  }

  @Test
  void deniedIsNotAllowed() {
    assertThat(new Denied().allowed()).isFalse();
  }

  @Test
  void allowedDefensivelyCopiesGrantedIds() {
    final var mutable = new java.util.HashSet<>(Set.of("a", "b"));
    final var allowed = new Allowed(mutable);

    mutable.add("c");

    assertThat(allowed.grantedResourceIds()).containsExactlyInAnyOrder("a", "b");
  }

  @Test
  void allowedRejectsEmptyGrantedIds() {
    assertThatThrownBy(() -> new Allowed(Set.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must not be empty");
  }
}
