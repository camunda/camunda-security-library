/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.scope;

/** What a runtime change did to one scope. */
public enum ScopeReloadOutcome {

  /** The scope had no chains; it is now served. */
  ADDED(true),

  /**
   * The scope's authentication changed. Its chains were replaced and its existing sessions are no
   * longer accepted.
   */
  REPLACED(true),

  /**
   * Only credentials changed (client secret, assertion keystore). The chains were replaced;
   * existing sessions stay valid and their next token request uses the new credential.
   */
  CREDENTIALS_ROTATED(true),

  /** The scope's key material was read again without a configuration change. */
  CREDENTIALS_REFRESHED(true),

  /** The descriptor equals the live one; nothing was rebuilt. */
  UNCHANGED(false),

  /** The scope was served and is now removed; its requests answer 404. */
  REMOVED(true),

  /** The scope to remove or refresh was not served. Nothing changed. */
  ABSENT(false),

  /**
   * The new configuration names an identity provider that could not be reached, so the scope keeps
   * serving its previous chains. The host should try again.
   */
  KEPT_PREVIOUS(false),

  /** Building the new chains failed. The scope keeps serving its previous chains, if any. */
  FAILED(false);

  private final boolean applied;

  ScopeReloadOutcome(final boolean applied) {
    this.applied = applied;
  }

  /** Whether the scope now serves what the change asked for. */
  public boolean applied() {
    return applied;
  }
}
