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

class ConfiguredTenantTest {

  @Test
  void shouldExposeAllComponentsViaAccessors() {
    final var tenant =
        new ConfiguredTenant(
            "tenant-1",
            "Tenant One",
            "the first tenant",
            List.of("user-a", "user-b"),
            List.of("client-a"),
            List.of("role-a"),
            List.of("group-a"),
            List.of("mapping-a"));

    assertThat(tenant.tenantId()).isEqualTo("tenant-1");
    assertThat(tenant.name()).isEqualTo("Tenant One");
    assertThat(tenant.description()).isEqualTo("the first tenant");
    assertThat(tenant.users()).containsExactly("user-a", "user-b");
    assertThat(tenant.clients()).containsExactly("client-a");
    assertThat(tenant.roles()).containsExactly("role-a");
    assertThat(tenant.groups()).containsExactly("group-a");
    assertThat(tenant.mappingRules()).containsExactly("mapping-a");
  }

  @Test
  void shouldAllowNullListComponents() {
    final var tenant = new ConfiguredTenant("tenant-1", null, null, null, null, null, null, null);

    assertThat(tenant.tenantId()).isEqualTo("tenant-1");
    assertThat(tenant.name()).isNull();
    assertThat(tenant.description()).isNull();
    assertThat(tenant.users()).isNull();
    assertThat(tenant.clients()).isNull();
    assertThat(tenant.roles()).isNull();
    assertThat(tenant.groups()).isNull();
    assertThat(tenant.mappingRules()).isNull();
  }
}
