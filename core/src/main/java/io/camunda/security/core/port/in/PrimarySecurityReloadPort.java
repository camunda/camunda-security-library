/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;

/**
 * Changes the security of the primary (unscoped) chains while the application runs, as {@link
 * ScopedSecurityReloadPort} changes a scope: issuer, audiences, client, claim mapping, providers
 * and credentials. The authentication method is fixed at startup.
 *
 * <p>A change builds the next generation of both primary chains off to the side — its own access
 * token decoder and OIDC client stack — checks it, and publishes it in one step; a request is
 * served by one generation, never by parts of two. A change of more than credentials ends the
 * sessions of the primary chains; a credential change keeps them.
 *
 * <p>The application's own beans the primary chains started with (decoder, client registrations,
 * authorized-client manager, token endpoint) serve only the startup generation. A change applies to
 * this node only.
 */
public interface PrimarySecurityReloadPort extends PrimaryCredentialsReloadPort {

  /**
   * As {@link #apply(AuthenticationConfiguration, UnreachableIdentityProviderPolicy)}, keeping the
   * previous generation while a new provider cannot be reached.
   */
  ScopeReloadResult apply(AuthenticationConfiguration authentication);

  /**
   * Serves the primary chains with {@code authentication} from now on.
   *
   * @param authentication built for this change alone; it must not be changed afterwards
   * @return {@code REPLACED}, {@code CREDENTIALS_ROTATED}, {@code UNCHANGED}, or {@code
   *     KEPT_PREVIOUS} / {@code FAILED} with the previous generation still serving
   * @throws IllegalArgumentException if {@code authentication} changes the authentication method
   */
  ScopeReloadResult apply(
      AuthenticationConfiguration authentication, UnreachableIdentityProviderPolicy policy);

  /** Builds the serving configuration again, for key material replaced at the same path. */
  ScopeReloadResult refreshCredentials();
}
