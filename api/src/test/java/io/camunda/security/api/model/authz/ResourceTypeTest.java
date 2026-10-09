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
  void processDefinitionSupportsSuspendProcessInstance() {
    assertThat(ResourceType.PROCESS_DEFINITION.getSupportedPermissionTypes())
        .contains(PermissionType.SUSPEND_PROCESS_INSTANCE);
  }

  @Test
  void batchSupportsCreateBatchOperationSuspendProcessInstance() {
    assertThat(ResourceType.BATCH.getSupportedPermissionTypes())
        .contains(PermissionType.CREATE_BATCH_OPERATION_SUSPEND_PROCESS_INSTANCE);
  }

  @Test
  void secretSupportsReadAndReveal() {
    assertThat(ResourceType.SECRET.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(PermissionType.READ, PermissionType.REVEAL);
  }

  @Test
  void buildResourcePermissionsMapHasSecretReadReveal() {
    final var map = ResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("SECRET")).containsExactlyInAnyOrder("READ", "REVEAL");
  }

  @Test
  void backupSupportsCreateReadDeleteRestore() {
    assertThat(ResourceType.BACKUP.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.DELETE,
            PermissionType.RESTORE);
  }

  @Test
  void buildResourcePermissionsMapHasBackupPermissions() {
    final var map = ResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("BACKUP")).containsExactlyInAnyOrder("CREATE", "READ", "DELETE", "RESTORE");
  }

  @Test
  void exporterSupportsPause() {
    assertThat(ResourceType.EXPORTER.getSupportedPermissionTypes())
        .containsExactly(PermissionType.PAUSE);
  }

  @Test
  void buildResourcePermissionsMapHasExporterPause() {
    final var map = ResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("EXPORTER")).containsExactly("PAUSE");
  }

  @Test
  void getSupportedPermissionTypesReturnsImmutableView() {
    final var permissions = ResourceType.COMPONENT.getSupportedPermissionTypes();

    assertThatThrownBy(() -> permissions.add(PermissionType.UPDATE))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(permissions::clear).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void workspaceSupportsRead() {
    assertThat(ResourceType.WORKSPACE.getSupportedPermissionTypes())
        .containsExactly(PermissionType.READ);
  }

  @Test
  void processApplicationSupportsHubPermissions() {
    assertThat(ResourceType.PROCESS_APPLICATION.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.UPDATE,
            PermissionType.DELETE,
            PermissionType.READ_SNAPSHOT,
            PermissionType.CREATE_SNAPSHOT,
            PermissionType.UPDATE_SNAPSHOT,
            PermissionType.DELETE_SNAPSHOT,
            PermissionType.REQUEST_REVIEW,
            PermissionType.SUBMIT_REVIEW);
  }

  @Test
  void workspaceDeclaresTheWorkspaceAttribute() {
    assertThat(ResourceType.WORKSPACE.getSupportedAttributes())
        .containsExactly(ResourceAttribute.WORKSPACE);
  }

  @Test
  void processApplicationDeclaresTheWorkspaceAttribute() {
    assertThat(ResourceType.PROCESS_APPLICATION.getSupportedAttributes())
        .containsExactly(ResourceAttribute.WORKSPACE);
  }

  @Test
  void userTaskDeclaresTheAttributesOfItsPropertyGrants() {
    assertThat(ResourceType.USER_TASK.getSupportedAttributes())
        .containsExactlyInAnyOrder(
            ResourceAttribute.ASSIGNEE,
            ResourceAttribute.CANDIDATE_USERS,
            ResourceAttribute.CANDIDATE_GROUPS);
  }

  @Test
  void otherResourceTypesDeclareNoAttributes() {
    assertThat(ResourceType.PROCESS_DEFINITION.getSupportedAttributes()).isEmpty();
    assertThat(ResourceType.UNSPECIFIED.getSupportedAttributes()).isEmpty();
  }

  @Test
  void supportedAttributesAreImmutable() {
    final var attributes = ResourceType.USER_TASK.getSupportedAttributes();

    assertThatThrownBy(attributes::clear).isInstanceOf(UnsupportedOperationException.class);
  }
}
