/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.authz.AuthorizationResourceType;

/**
 * Extension point for scope-restricted role memberships. Returns the opaque scope ID a resource
 * belongs to, so that only the principal's roles scoped to that ID (plus its unscoped roles)
 * contribute to the authorization check on the resource.
 *
 * <p>Implementations are registered in a {@code ResourceScopeExtractorRegistry} (core module).
 * Several extractors may share a {@link #resourceType()} as long as their {@link #resourceClass()}
 * differs; the one whose class accepts the checked resource is used.
 *
 * @param <T> the resource type this extractor operates on
 */
public interface ResourceScopeExtractor<T> {

  /** The resource type whose checks this extractor scopes. */
  AuthorizationResourceType resourceType();

  /** The class of resources this extractor handles; a resource matches if it is an instance. */
  Class<T> resourceClass();

  /**
   * Returns the scope ID of {@code resource}, or {@code null} if the resource belongs to no scope,
   * in which case only unscoped roles apply.
   */
  String scopeIdOf(T resource);
}
