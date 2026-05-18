/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ConfiguredUserTest {

  @Test
  void shouldStoreAllFieldsFromConstructor() {
    final var user = new ConfiguredUser("alice", "secret", "Alice Doe", "alice@example.com");

    assertThat(user.getUsername()).isEqualTo("alice");
    assertThat(user.getPassword()).isEqualTo("secret");
    assertThat(user.getName()).isEqualTo("Alice Doe");
    assertThat(user.getEmail()).isEqualTo("alice@example.com");
  }

  @Test
  void shouldUpdateFieldsViaSetters() {
    final var user = new ConfiguredUser("alice", "secret", "Alice Doe", "alice@example.com");

    user.setUsername("bob");
    user.setPassword("hunter2");
    user.setName("Bob Roe");
    user.setEmail("bob@example.com");

    assertThat(user.getUsername()).isEqualTo("bob");
    assertThat(user.getPassword()).isEqualTo("hunter2");
    assertThat(user.getName()).isEqualTo("Bob Roe");
    assertThat(user.getEmail()).isEqualTo("bob@example.com");
  }

  @Test
  void shouldAcceptNullFields() {
    final var user = new ConfiguredUser(null, null, null, null);

    assertThat(user.getUsername()).isNull();
    assertThat(user.getPassword()).isNull();
    assertThat(user.getName()).isNull();
    assertThat(user.getEmail()).isNull();
  }
}
