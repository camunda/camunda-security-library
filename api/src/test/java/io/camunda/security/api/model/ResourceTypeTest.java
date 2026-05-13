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

import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.api.model.authz.ResourceType;
import org.junit.jupiter.api.Test;

class ResourceTypeTest {

  @Test
  void componentSupportsAccess() {
    assertThat(ResourceType.COMPONENT.getSupportedPermissionTypes())
        .containsExactly(PermissionType.ACCESS);
  }

  @Test
  void getUserProvidedResourceTypesExcludesUnspecified() {
    assertThat(ResourceType.getUserProvidedResourceTypes())
        .doesNotContain(ResourceType.UNSPECIFIED)
        .contains(ResourceType.COMPONENT, ResourceType.USER_TASK);
  }

  @Test
  void buildResourcePermissionsMapHasComponentAccess() {
    final var map = ResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("COMPONENT")).containsExactly("ACCESS");
  }

  @Test
  void getSupportedPermissionTypesReturnsImmutableView() {
    final var permissions = ResourceType.COMPONENT.getSupportedPermissionTypes();

    assertThatThrownBy(() -> permissions.add(PermissionType.UPDATE))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(permissions::clear).isInstanceOf(UnsupportedOperationException.class);
  }
}
