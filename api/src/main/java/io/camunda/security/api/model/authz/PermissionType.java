/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

/** Permissions a principal can be granted on a resource. */
public enum PermissionType {
  /** Common usage permissions. */
  ACCESS(true),
  CREATE,
  DELETE,
  DELETE_DRD,
  DELETE_FORM,
  DELETE_PROCESS,
  DELETE_RESOURCE,
  READ(true),
  READ_JOB_METRIC(true),
  READ_USAGE_METRIC(true),
  UPDATE,

  /** Engine usage permissions. */
  CANCEL_PROCESS_INSTANCE,
  CLAIM,
  CLAIM_USER_TASK,
  COMPLETE,
  COMPLETE_USER_TASK,
  CREATE_BATCH_OPERATION_CANCEL_PROCESS_INSTANCE,
  CREATE_BATCH_OPERATION_DELETE_DECISION_DEFINITION,
  CREATE_BATCH_OPERATION_DELETE_DECISION_INSTANCE,
  CREATE_BATCH_OPERATION_DELETE_PROCESS_DEFINITION,
  CREATE_BATCH_OPERATION_DELETE_PROCESS_INSTANCE,
  CREATE_BATCH_OPERATION_MIGRATE_PROCESS_INSTANCE,
  CREATE_BATCH_OPERATION_MODIFY_PROCESS_INSTANCE,
  CREATE_BATCH_OPERATION_RESOLVE_INCIDENT,
  CREATE_BATCH_OPERATION_UPDATE_JOB,
  CREATE_DECISION_INSTANCE,
  CREATE_PROCESS_INSTANCE,
  CREATE_TASK_LISTENER,
  DELETE_DECISION_INSTANCE,
  DELETE_PROCESS_INSTANCE,
  DELETE_TASK_LISTENER,
  EVALUATE,
  MODIFY_PROCESS_INSTANCE,
  READ_DECISION_DEFINITION(true),
  READ_DECISION_INSTANCE(true),
  READ_PROCESS_DEFINITION(true),
  READ_PROCESS_INSTANCE(true),
  READ_TASK_LISTENER(true),
  READ_USER_TASK(true),
  UPDATE_PROCESS_INSTANCE,
  UPDATE_TASK_LISTENER,
  UPDATE_USER_TASK;

  private final boolean isReadPermission;

  PermissionType(final boolean isReadPermission) {
    this.isReadPermission = isReadPermission;
  }

  PermissionType() {
    isReadPermission = false;
  }

  public boolean isReadPermission() {
    return isReadPermission;
  }
}
