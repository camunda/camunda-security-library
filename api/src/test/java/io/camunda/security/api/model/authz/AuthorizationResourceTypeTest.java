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

class AuthorizationResourceTypeTest {

  @Test
  void componentSupportsAccess() {
    assertThat(AuthorizationResourceType.COMPONENT.getSupportedPermissionTypes())
        .containsExactly(PermissionType.ACCESS);
  }

  @Test
  void getUserProvidedResourceTypesExcludesUnspecified() {
    assertThat(AuthorizationResourceType.getUserProvidedResourceTypes())
        .doesNotContain(AuthorizationResourceType.UNSPECIFIED)
        .contains(AuthorizationResourceType.COMPONENT, AuthorizationResourceType.USER_TASK);
  }

  @Test
  void buildResourcePermissionsMapHasComponentAccess() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("COMPONENT")).containsExactly("ACCESS");
  }

  @Test
  void processDefinitionSupportsSuspendProcessInstance() {
    assertThat(AuthorizationResourceType.PROCESS_DEFINITION.getSupportedPermissionTypes())
        .contains(PermissionType.SUSPEND_PROCESS_INSTANCE);
  }

  @Test
  void batchSupportsCreateBatchOperationSuspendProcessInstance() {
    assertThat(AuthorizationResourceType.BATCH.getSupportedPermissionTypes())
        .contains(PermissionType.CREATE_BATCH_OPERATION_SUSPEND_PROCESS_INSTANCE);
  }

  @Test
  void secretSupportsReadAndReveal() {
    assertThat(AuthorizationResourceType.SECRET.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(PermissionType.READ, PermissionType.REVEAL);
  }

  @Test
  void buildResourcePermissionsMapHasSecretReadReveal() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("SECRET")).containsExactlyInAnyOrder("READ", "REVEAL");
  }

  @Test
  void backupSupportsCreateReadDeleteRestore() {
    assertThat(AuthorizationResourceType.BACKUP.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.DELETE,
            PermissionType.RESTORE);
  }

  @Test
  void buildResourcePermissionsMapHasBackupPermissions() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("BACKUP")).containsExactlyInAnyOrder("CREATE", "READ", "DELETE", "RESTORE");
  }

  @Test
  void exporterSupportsPause() {
    assertThat(AuthorizationResourceType.EXPORTER.getSupportedPermissionTypes())
        .containsExactly(PermissionType.PAUSE);
  }

  @Test
  void buildResourcePermissionsMapHasExporterPause() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("EXPORTER")).containsExactly("PAUSE");
  }

  @Test
  void getSupportedPermissionTypesReturnsImmutableView() {
    final var permissions = AuthorizationResourceType.COMPONENT.getSupportedPermissionTypes();

    assertThatThrownBy(() -> permissions.add(PermissionType.UPDATE))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(permissions::clear).isInstanceOf(UnsupportedOperationException.class);
  }
}
