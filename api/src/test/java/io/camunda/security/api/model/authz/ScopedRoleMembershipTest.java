/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ScopedRoleMembershipTest {

  @Test
  void constructorKeepsRoleIdAndScopeId() {
    final var membership = new ScopedRoleMembership("editor", "w1");
    assertThat(membership.roleId()).isEqualTo("editor");
    assertThat(membership.scopeId()).isEqualTo("w1");
  }

  @Test
  void constructorWithNullRoleIdThrowsNullPointerException() {
    assertThatThrownBy(() -> new ScopedRoleMembership(null, "w1"))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void constructorWithNullScopeIdThrowsNullPointerException() {
    assertThatThrownBy(() -> new ScopedRoleMembership("editor", null))
        .isInstanceOf(NullPointerException.class);
  }
}
