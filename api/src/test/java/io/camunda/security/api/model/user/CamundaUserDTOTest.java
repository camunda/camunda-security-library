/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class CamundaUserDTOTest {

  @Test
  void normalisesNullCollectionsToEmpty() {
    final var dto =
        new CamundaUserDTO(
            "Alice", "Alice", "alice@example.com", null, null, null, null, "free",  true);

    assertThat(dto.authorizedComponents()).isEmpty();
    assertThat(dto.tenants()).isEmpty();
    assertThat(dto.groups()).isEmpty();
    assertThat(dto.roles()).isEmpty();
  }

  @Test
  void preservesSuppliedCollectionsAndScalars() {
    final var tenants = List.of("tenant-1", "tenant-2");
    final var groups = List.of("group-1");
    final var roles = List.of("admin");
    final var components = List.of("operate", "tasklist");

    final var dto =
        new CamundaUserDTO(
            "Alice",
            "Alice",
            "alice@example.com",
            components,
            tenants,
            groups,
            roles,
            "enterprise",
            false);

    assertThat(dto.displayName()).isEqualTo("Alice");
    assertThat(dto.username()).isEqualTo("Alice");
    assertThat(dto.email()).isEqualTo("alice@example.com");
    assertThat(dto.authorizedComponents()).isEqualTo(components);
    assertThat(dto.tenants()).isEqualTo(tenants);
    assertThat(dto.groups()).isEqualTo(groups);
    assertThat(dto.roles()).isEqualTo(roles);
    assertThat(dto.salesPlanType()).isEqualTo("enterprise");
    assertThat(dto.canLogout()).isFalse();
  }
}
