/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

/**
 * Closed catalogue of the authenticated attributes of a principal that an {@link Operand.Principal}
 * can refer to. The values are resolved from the {@code CamundaAuthentication} when a condition is
 * evaluated.
 */
public enum PrincipalAttribute {
  /** The authenticated username. */
  USERNAME,
  /** The authenticated client ID. */
  CLIENT_ID,
  /** The IDs of the groups of the principal. */
  GROUP_IDS,
  /** The IDs of the tenants of the principal. */
  TENANT_IDS
}
