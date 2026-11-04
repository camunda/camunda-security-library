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

/**
 * Replaces the OIDC client credentials of the primary (unscoped) chains while the application runs:
 * the client secret and the {@code private_key_jwt} keystore of the default slot and of every named
 * provider. Nothing else of the primary chains changes, so no chain, decoder, validator or claim
 * converter is rebuilt and every session is kept.
 *
 * <p>A rotation builds the new client registrations next to the ones in use, checks that the
 * identity provider accepts the new credentials, and only then publishes them. Login, refresh and
 * revocation token requests that start after the publish use the new credentials, including those
 * of sessions created before it.
 *
 * <p>The library reads {@code private_key_jwt} key material from the keystore on every token
 * request, so a keystore replaced at the same path with the same passwords is used at once and
 * needs no call; a host that caches signing keys itself must drop them.
 *
 * <p>A change applies to this node only. A host with several nodes calls it on each of them. The
 * scoped chains are not touched; change them through {@link ScopedSecurityReloadPort}.
 */
public interface PrimaryCredentialsReloadPort {

  /**
   * Replaces the credentials of the primary chains with those of {@code authentication}.
   *
   * @param authentication the primary authentication configuration with new credentials; it must
   *     not be changed afterwards
   * @return {@code CREDENTIALS_ROTATED} once the new credentials are used, {@code UNCHANGED} when
   *     they are the ones in use, or {@code KEPT_PREVIOUS} when the identity provider rejected them
   *     or could not be asked; the previous credentials are then still used
   * @throws IllegalArgumentException if {@code authentication} changes more than credentials
   */
  ScopeReloadResult rotateCredentials(AuthenticationConfiguration authentication);
}
