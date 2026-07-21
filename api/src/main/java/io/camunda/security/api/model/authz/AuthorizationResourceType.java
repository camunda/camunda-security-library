/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.util.*;
import java.util.stream.Collectors;

public enum AuthorizationResourceType {
  /** Common identity and authorization resources. */
  AUDIT_LOG(PermissionType.READ),
  AUTHORIZATION(
      PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),
  BACKUP(PermissionType.CREATE, PermissionType.READ, PermissionType.DELETE, PermissionType.RESTORE),
  CLUSTER_VARIABLE(
      PermissionType.CREATE, PermissionType.DELETE, PermissionType.UPDATE, PermissionType.READ),
  COMPONENT(PermissionType.ACCESS),
  DOCUMENT(PermissionType.CREATE, PermissionType.READ, PermissionType.DELETE),
  GROUP(PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),
  MAPPING_RULE(
      PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),
  MESSAGE(PermissionType.CREATE, PermissionType.READ),
  RESOURCE(
      PermissionType.CREATE,
      PermissionType.READ,
      PermissionType.DELETE_DRD,
      PermissionType.DELETE_FORM,
      PermissionType.DELETE_PROCESS,
      PermissionType.DELETE_RESOURCE),
  ROLE(PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),
  SECRET(PermissionType.READ, PermissionType.REVEAL),
  SYSTEM(
      PermissionType.READ,
      PermissionType.READ_USAGE_METRIC,
      PermissionType.READ_JOB_METRIC,
      PermissionType.UPDATE),
  TENANT(PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),
  USER(PermissionType.CREATE, PermissionType.READ, PermissionType.UPDATE, PermissionType.DELETE),

  /** Engine-related resources. */
  BATCH(
      PermissionType.CREATE,
      PermissionType.CREATE_BATCH_OPERATION_CANCEL_PROCESS_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_DELETE_PROCESS_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_MIGRATE_PROCESS_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_MODIFY_PROCESS_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_RESOLVE_INCIDENT,
      PermissionType.CREATE_BATCH_OPERATION_SUSPEND_PROCESS_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_UPDATE_JOB,
      PermissionType.CREATE_BATCH_OPERATION_DELETE_DECISION_INSTANCE,
      PermissionType.CREATE_BATCH_OPERATION_DELETE_DECISION_DEFINITION,
      PermissionType.CREATE_BATCH_OPERATION_DELETE_PROCESS_DEFINITION,
      PermissionType.READ,
      PermissionType.UPDATE),
  DECISION_DEFINITION(
      PermissionType.CREATE_DECISION_INSTANCE,
      PermissionType.READ_DECISION_DEFINITION,
      PermissionType.READ_DECISION_INSTANCE,
      PermissionType.DELETE_DECISION_INSTANCE),
  DECISION_REQUIREMENTS_DEFINITION(PermissionType.READ),
  EXPORTER(PermissionType.PAUSE),
  EXPRESSION(PermissionType.EVALUATE),
  GLOBAL_LISTENER(
      PermissionType.CREATE_TASK_LISTENER,
      PermissionType.READ_TASK_LISTENER,
      PermissionType.UPDATE_TASK_LISTENER,
      PermissionType.DELETE_TASK_LISTENER),
  PROCESS_DEFINITION(
      PermissionType.CREATE_PROCESS_INSTANCE,
      PermissionType.CLAIM_USER_TASK,
      PermissionType.READ_PROCESS_DEFINITION,
      PermissionType.READ_PROCESS_INSTANCE,
      PermissionType.READ_USER_TASK,
      PermissionType.UPDATE_PROCESS_INSTANCE,
      PermissionType.UPDATE_USER_TASK,
      PermissionType.MODIFY_PROCESS_INSTANCE,
      PermissionType.COMPLETE_USER_TASK,
      PermissionType.CANCEL_PROCESS_INSTANCE,
      PermissionType.DELETE_PROCESS_INSTANCE,
      PermissionType.SUSPEND_PROCESS_INSTANCE),
  USER_TASK(
      PermissionType.READ, PermissionType.UPDATE, PermissionType.CLAIM, PermissionType.COMPLETE),
  UNSPECIFIED();

  private final Set<PermissionType> supportedPermissionTypes;

  AuthorizationResourceType(final PermissionType... supportedPermissionTypes) {
    this.supportedPermissionTypes = Set.copyOf(Arrays.asList(supportedPermissionTypes));
  }

  public Set<PermissionType> getSupportedPermissionTypes() {
    return supportedPermissionTypes;
  }

  /**
   * Returns all the resource types that are user provided. This is everything in this enum, except
   * for UNSPECIFIED. UNSPECIFIED is only used as a default internally. By having this we prevent
   * accidentally creating a wrong permission because the resource type wasn't set properly.
   *
   * @return a set of all user provided resource types
   */
  public static Set<AuthorizationResourceType> getUserProvidedResourceTypes() {
    return Arrays.stream(values()).filter(type -> type != UNSPECIFIED).collect(Collectors.toSet());
  }

  /**
   * Builds a map with the key as the name of the resource type and the value is a list of
   * permission types allowed for that resource type.
   *
   * @return
   */
  public static Map<String, List<String>> buildResourcePermissionsMap() {
    return AuthorizationResourceType.getUserProvidedResourceTypes().stream()
        .sorted(Comparator.comparing(Enum::name))
        .collect(
            Collectors.toMap(
                Enum::name,
                resourceType ->
                    resourceType.getSupportedPermissionTypes().stream()
                        .map(PermissionType::name)
                        .sorted()
                        .collect(Collectors.toList()),
                (e1, e2) -> e1,
                LinkedHashMap::new));
  }
}
