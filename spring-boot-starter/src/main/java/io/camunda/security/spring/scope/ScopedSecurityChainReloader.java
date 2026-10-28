/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

/**
 * Rebuilds the scoped security chains from the current {@link
 * io.camunda.security.api.context.CamundaSecurityScopeProvider} descriptors while the application
 * runs, so scopes can be added, reconfigured and removed without a restart.
 *
 * <p>A scope present at startup gets freshly built chains swapped in; once it is no longer
 * contributed its requests answer 404. A scope that was not present at startup is served through
 * {@link DynamicScopedSecurityFilterChain} and simply dropped when it goes away.
 *
 * <p>A scope that is no longer contributed also releases its session filter and session repository.
 * A scope that stays keeps them, so an existing session stays valid after the scope's
 * authentication configuration changed.
 */
public interface ScopedSecurityChainReloader {

  /**
   * Re-reads the descriptors and swaps the chains. Nothing is swapped if any descriptor fails to
   * build.
   */
  void reload();
}
