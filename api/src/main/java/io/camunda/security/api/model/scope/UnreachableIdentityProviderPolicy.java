/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.scope;

/**
 * What a change to a served scope does when an identity provider of its new configuration cannot be
 * reached. A scope that is not served yet always applies its configuration: it has nothing to keep,
 * and its requests recover once the provider answers (ADR-0025).
 */
public enum UnreachableIdentityProviderPolicy {

  /**
   * Keep serving the previous chains and report {@link ScopeReloadOutcome#KEPT_PREVIOUS}. The
   * previous configuration keeps being trusted until a later change succeeds.
   */
  KEEP_PREVIOUS,

  /**
   * Apply the new configuration anyway. Requests that need the unreachable provider fail with a
   * server error until it answers, and recover without another change. Use it when the change
   * withdraws trust from a provider of the previous configuration.
   */
  APPLY
}
