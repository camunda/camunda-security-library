/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.Map;
import java.util.Set;

/**
 * Extension point for conditional role memberships and attribute-based grants. Returns the values
 * of the attributes of a resource, which {@link io.camunda.security.api.model.authz.Condition}s are
 * evaluated against.
 *
 * <p>Implementations are registered in a {@code ResourceAttributeExtractorRegistry} (core module).
 * Several extractors may share a {@link #resourceType()} as long as their {@link #resourceClass()}
 * differs; the one whose class accepts the checked resource is used. An extractor declares the
 * attributes it provides with {@link #providedAttributes()}, which must be attributes that its
 * resource type declares; the registry rejects other extractors at construction and rejects
 * attributes outside the declaration when it reads them.
 *
 * @param <T> the resource type this extractor operates on
 */
public interface ResourceAttributeExtractor<T> {

  /** The resource type whose checks this extractor serves. */
  AuthorizationResourceType resourceType();

  /** The class of resources this extractor handles; a resource matches if it is an instance. */
  Class<T> resourceClass();

  /** The attributes this extractor can provide, a subset of those its resource type declares. */
  Set<ResourceAttribute> providedAttributes();

  /**
   * Returns the values of the attributes of {@code resource}. An attribute the resource does not
   * have is absent from the map or has no values. Null and empty values count as absent.
   */
  Map<ResourceAttribute, Set<String>> attributesOf(T resource);
}
