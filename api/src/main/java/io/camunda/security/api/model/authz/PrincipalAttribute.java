/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

/**
 * The attributes of the caller that an {@link Operand.Principal} can refer to. The values are taken
 * from the caller's {@code CamundaAuthentication} when a condition is evaluated.
 *
 * <p>Only trusted attributes may be used (ADR-0041): the caller's identity always, and group and
 * tenant IDs only when the host resolves them from its identity store. A condition on group or
 * tenant IDs taken from a token claim denies.
 */
public enum PrincipalAttribute {
  /** The authenticated username. */
  USERNAME,
  /** The authenticated client ID. */
  CLIENT_ID,
  /** The IDs of the caller's groups. */
  GROUP_IDS,
  /** The IDs of the caller's tenants. */
  TENANT_IDS
}
