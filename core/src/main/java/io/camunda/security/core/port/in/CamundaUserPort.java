/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.user.CamundaUserDTO;

/**
 * Inbound port returning the currently-authenticated user. Host applications call this from REST
 * controllers (for example {@code GET /v2/authentication/me}) to materialise the user view that
 * pairs with {@link io.camunda.security.api.model.CamundaAuthentication}.
 *
 * <p>Implementations may vary by authentication method (basic, OIDC) and deployment shape
 * (secondary-storage-backed, no-DB). The library ships defaults for non-storage-backed cases; hosts
 * supply richer implementations via {@code @ConditionalOnMissingBean} overrides.
 */
public interface CamundaUserPort {

  /** Returns the current user view, populated from the active authentication context. */
  CamundaUserDTO getCurrentUser();

  /**
   * Returns the bearer token (or token-equivalent credential) associated with the current
   * authentication, or {@code null} when no token applies (for example basic authentication).
   */
  String getUserToken();
}
