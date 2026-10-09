/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

/**
 * Closed catalogue of the attributes of a resource that a {@link Condition} can refer to. Each
 * {@link AuthorizationResourceType} declares the attributes its resources can provide through
 * {@link AuthorizationResourceType#getSupportedAttributes()}. Attributes may be multi-valued.
 */
public enum ResourceAttribute {
  /** The ID of the workspace a resource belongs to, or of the workspace itself. */
  WORKSPACE,
  /** The user a user task is assigned to. */
  ASSIGNEE,
  /** The users that are candidates for a user task. */
  CANDIDATE_USERS,
  /** The groups that are candidates for a user task. */
  CANDIDATE_GROUPS
}
