/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Map;

/** Inbound port for reading the merged OIDC provider configuration keyed by registration ID. */
public interface OidcProviderConfigurationPort {

  /**
   * Returns the OIDC authentication configuration for the given registration ID.
   *
   * @param registrationId the OIDC provider registration ID
   * @return the matching {@link OidcConfiguration}, or {@code null} if no configuration exists for
   *     the given registration ID
   */
  OidcConfiguration getOidcAuthenticationConfigurationById(String registrationId);

  /**
   * Returns an immutable map of all OIDC authentication configurations keyed by registration ID.
   *
   * <p>The returned map is a defensive copy of the internal configuration state and cannot be
   * mutated. Attempts to modify the returned map will throw {@link UnsupportedOperationException}.
   * Callers should treat this map as read-only; any mutations to the internal repository must go
   * through dedicated mutator methods on the repository implementation.
   *
   * @return an immutable map of registration IDs to {@link OidcConfiguration} objects; never {@code
   *     null}, may be empty
   */
  Map<String, OidcConfiguration> getOidcAuthenticationConfigurations();
}
