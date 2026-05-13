/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.Authorization;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationTest {

  @Test
  void exposesResourceTypeIdAndPermissions() {
    final var authorization =
        new Authorization(ResourceType.COMPONENT, "operate", Set.of(PermissionType.ACCESS));

    assertThat(authorization.resourceType()).isEqualTo(ResourceType.COMPONENT);
    assertThat(authorization.resourceId()).isEqualTo("operate");
    assertThat(authorization.permissionTypes()).containsExactly(PermissionType.ACCESS);
  }

  @Test
  void rejectsNullResourceType() {
    assertThatThrownBy(() -> new Authorization(null, "operate", Set.of(PermissionType.ACCESS)))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("resourceType");
  }

  @Test
  void rejectsNullResourceId() {
    assertThatThrownBy(
            () -> new Authorization(ResourceType.COMPONENT, null, Set.of(PermissionType.ACCESS)))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("resourceId");
  }

  @Test
  void nullPermissionsBecomesEmpty() {
    final var authorization = new Authorization(ResourceType.COMPONENT, "operate", null);
    assertThat(authorization.permissionTypes()).isEmpty();
  }

  @Test
  void permissionsAreImmutableAfterConstruction() {
    final var mutable = new java.util.HashSet<>(Set.of(PermissionType.ACCESS, PermissionType.READ));
    final var authorization = new Authorization(ResourceType.COMPONENT, "operate", mutable);

    mutable.add(PermissionType.UPDATE);

    assertThat(authorization.permissionTypes())
        .containsExactlyInAnyOrder(PermissionType.ACCESS, PermissionType.READ);
  }
}
