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

class ConfiguredGroupTest {

  @Test
  void shouldExposeAllComponentsViaAccessors() {
    final var group =
        new ConfiguredGroup(
            "group-1",
            "Group One",
            "the first group",
            List.of("user-a", "user-b"),
            List.of("role-a"),
            List.of("mapping-a"),
            List.of("client-a"));

    assertThat(group.groupId()).isEqualTo("group-1");
    assertThat(group.name()).isEqualTo("Group One");
    assertThat(group.description()).isEqualTo("the first group");
    assertThat(group.users()).containsExactly("user-a", "user-b");
    assertThat(group.roles()).containsExactly("role-a");
    assertThat(group.mappingRules()).containsExactly("mapping-a");
    assertThat(group.clients()).containsExactly("client-a");
  }

  @Test
  void shouldAllowNullOptionalComponents() {
    final var group = new ConfiguredGroup("group-1", null, null, null, null, null, null);

    assertThat(group.groupId()).isEqualTo("group-1");
    assertThat(group.name()).isNull();
    assertThat(group.description()).isNull();
    assertThat(group.users()).isNull();
    assertThat(group.roles()).isNull();
    assertThat(group.mappingRules()).isNull();
    assertThat(group.clients()).isNull();
  }
}
