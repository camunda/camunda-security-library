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
  void processDefinitionSupportsSuspendProcessDefinition() {
    assertThat(AuthorizationResourceType.PROCESS_DEFINITION.getSupportedPermissionTypes())
        .contains(PermissionType.SUSPEND_PROCESS_DEFINITION);
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
  void probeSupportsCreateAndAnswer() {
    assertThat(AuthorizationResourceType.PROBE.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(PermissionType.CREATE, PermissionType.ANSWER);
  }

  @Test
  void buildResourcePermissionsMapHasProbeCreateAnswer() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map).doesNotContainKey("UNSPECIFIED");
    assertThat(map.get("PROBE")).containsExactly("ANSWER", "CREATE");
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

  @Test
  void workspaceSupportsCreateReadUpdateDeleteRestorePurge() {
    assertThat(AuthorizationResourceType.WORKSPACE.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.UPDATE,
            PermissionType.DELETE,
            PermissionType.RESTORE,
            PermissionType.PURGE);
  }

  @Test
  void fileSupportsAllContentPermissions() {
    assertThat(AuthorizationResourceType.FILE.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.UPDATE,
            PermissionType.DELETE,
            PermissionType.RESTORE,
            PermissionType.PURGE,
            PermissionType.DEPLOY,
            PermissionType.EXECUTE,
            PermissionType.SHARE);
  }

  @Test
  void projectSnapshotSupportsReviewPermissions() {
    assertThat(AuthorizationResourceType.PROJECT_SNAPSHOT.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.CREATE,
            PermissionType.READ,
            PermissionType.UPDATE,
            PermissionType.DELETE,
            PermissionType.RESTORE,
            PermissionType.REQUEST_REVIEW,
            PermissionType.SUBMIT_REVIEW);
  }

  @Test
  void catalogSupportsReadUsageAndCrud() {
    assertThat(AuthorizationResourceType.CATALOG.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(
            PermissionType.READ,
            PermissionType.READ_USAGE_METRIC,
            PermissionType.CREATE,
            PermissionType.UPDATE,
            PermissionType.DELETE);
  }

  @Test
  void businessValueSupportsReadUpdate() {
    assertThat(AuthorizationResourceType.BUSINESS_VALUE.getSupportedPermissionTypes())
        .containsExactlyInAnyOrder(PermissionType.READ, PermissionType.UPDATE);
  }

  @Test
  void buildResourcePermissionsMapHasHubTypes() {
    final var map = AuthorizationResourceType.buildResourcePermissionsMap();

    assertThat(map.get("WORKSPACE"))
        .containsExactlyInAnyOrder("CREATE", "READ", "UPDATE", "DELETE", "RESTORE", "PURGE");
    assertThat(map.get("FILE"))
        .containsExactlyInAnyOrder(
            "CREATE", "READ", "UPDATE", "DELETE", "RESTORE", "PURGE", "DEPLOY", "EXECUTE", "SHARE");
    assertThat(map)
        .containsKeys(
            "BUSINESS_VALUE",
            "CATALOG",
            "CATALOG_ASSET",
            "CLUSTER",
            "COMMENT",
            "ENVIRONMENT",
            "GIT_SYNC",
            "PROJECT",
            "PROJECT_SNAPSHOT",
            "VERSION");
  }

  @Test
  void getUserProvidedResourceTypesIncludesHubTypes() {
    assertThat(AuthorizationResourceType.getUserProvidedResourceTypes())
        .contains(
            AuthorizationResourceType.WORKSPACE,
            AuthorizationResourceType.PROJECT,
            AuthorizationResourceType.FILE);
  }
}
