/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.scope.ScopeReloadReport;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.api.model.scope.UnreachableIdentityProviderPolicy;

/**
 * Changes the security of scopes while the application runs, without a restart (ADR-0040).
 *
 * <p>Every change builds the scope's chains first and publishes them in one step, so a request sees
 * either the previous generation of a scope or the new one, never a mix. A change that fails leaves
 * the scope's previous chains and every other scope untouched. Changes to one scope are serialized;
 * changes to different scopes run in parallel.
 *
 * <p>The scope providers stay the source of truth: {@link #reloadAll()} and a restart read them, so
 * a host that applies a change through this port must also return it from its provider.
 *
 * <p>A change applies to this node only. A host with several nodes calls it on each of them.
 */
public interface ScopedSecurityReloadPort {

  /**
   * Reads every scope provider and applies the difference: adds new scopes, rebuilds changed ones
   * and removes those no longer contributed. Scopes whose descriptor is unchanged are not rebuilt.
   *
   * @throws IllegalStateException when the contributed set is invalid as a whole (duplicate base
   *     paths, colliding cookie names); nothing is changed then
   */
  ScopeReloadReport reloadAll();

  /**
   * Adds the scope, or replaces it when it is already served, keeping the previous chains when an
   * identity provider of the new configuration cannot be reached.
   */
  ScopeReloadResult apply(ScopedSecurityDescriptor descriptor);

  /** Adds or replaces the scope, with an explicit policy for an unreachable identity provider. */
  ScopeReloadResult apply(
      ScopedSecurityDescriptor descriptor, UnreachableIdentityProviderPolicy policy);

  /**
   * Stops serving the scope. Its requests answer 404 from then on, and its sessions are no longer
   * accepted.
   */
  ScopeReloadResult remove(String basePath);

  /**
   * Replaces the scope's credentials (OIDC client secret, assertion keystore location and
   * passwords) and keeps its sessions.
   *
   * @throws IllegalArgumentException when the descriptor changes more than credentials, or the
   *     scope is not served; use {@link #apply} for those
   */
  ScopeReloadResult rotateCredentials(ScopedSecurityDescriptor descriptor);

  /**
   * Reads the scope's key material again — for example a keystore replaced at the same path —
   * without a configuration change, and keeps its sessions.
   */
  ScopeReloadResult refreshCredentials(String basePath);
}
