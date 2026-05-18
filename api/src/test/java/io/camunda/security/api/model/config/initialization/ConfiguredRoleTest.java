/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class ConfiguredRoleTest {

  @Test
  void shouldExposeAllComponentsViaAccessors() {
    final var role =
        new ConfiguredRole(
            "role-1",
            "Role One",
            "the first role",
            List.of("user-a", "user-b"),
            List.of("client-a"),
            List.of("mapping-a"),
            List.of("group-a"));

    assertThat(role.roleId()).isEqualTo("role-1");
    assertThat(role.name()).isEqualTo("Role One");
    assertThat(role.description()).isEqualTo("the first role");
    assertThat(role.users()).containsExactly("user-a", "user-b");
    assertThat(role.clients()).containsExactly("client-a");
    assertThat(role.mappingRules()).containsExactly("mapping-a");
    assertThat(role.groups()).containsExactly("group-a");
  }

  @Test
  void shouldAllowNullOptionalComponents() {
    final var role = new ConfiguredRole("role-1", null, null, null, null, null, null);

    assertThat(role.roleId()).isEqualTo("role-1");
    assertThat(role.name()).isNull();
    assertThat(role.description()).isNull();
    assertThat(role.users()).isNull();
    assertThat(role.clients()).isNull();
    assertThat(role.mappingRules()).isNull();
    assertThat(role.groups()).isNull();
  }
}
