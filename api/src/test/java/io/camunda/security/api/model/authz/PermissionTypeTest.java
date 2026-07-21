/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PermissionTypeTest {

  @Test
  void readPermissionsAreFlagged() {
    assertThat(PermissionType.READ.isReadPermission()).isTrue();
    assertThat(PermissionType.READ_PROCESS_DEFINITION.isReadPermission()).isTrue();
    assertThat(PermissionType.ACCESS.isReadPermission()).isTrue();
  }

  @Test
  void writePermissionsAreNotReadPermissions() {
    assertThat(PermissionType.UPDATE.isReadPermission()).isFalse();
    assertThat(PermissionType.DELETE.isReadPermission()).isFalse();
    assertThat(PermissionType.CREATE.isReadPermission()).isFalse();
  }

  @Test
  void suspendProcessInstancePermissionsAreNotReadPermissions() {
    assertThat(PermissionType.SUSPEND_PROCESS_INSTANCE.isReadPermission()).isFalse();
    assertThat(PermissionType.CREATE_BATCH_OPERATION_SUSPEND_PROCESS_INSTANCE.isReadPermission())
        .isFalse();
  }

  @Test
  void revealIsNotFlaggedAsReadPermission() {
    // REVEAL exposes secret values, so it must not be treated as a read permission.
    assertThat(PermissionType.REVEAL.isReadPermission()).isFalse();
  }

  @Test
  void pauseIsNotFlaggedAsReadPermission() {
    // PAUSE is a control operation (e.g. pausing exporting), not a read.
    assertThat(PermissionType.PAUSE.isReadPermission()).isFalse();
  }
}
