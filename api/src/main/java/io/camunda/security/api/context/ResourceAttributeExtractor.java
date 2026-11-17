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
 * Extension point for conditional memberships (ADR-0041). Gives the values of the attributes of a
 * resource. The conditions of a {@link io.camunda.security.api.model.authz.ConditionalMembership}
 * are evaluated against these values.
 *
 * <p>Implementations are registered in a {@code ResourceAttributeExtractorRegistry} (core module).
 * The extractors of one {@link #resourceType()} must have unrelated {@link #resourceClass()
 * classes}: the registry rejects two classes of which one is the same as, or a subtype of, the
 * other. If more than one extractor still accepts a resource, for example two interfaces that the
 * resource both implements, none is used and conditional memberships do not count.
 *
 * <p>A conditional membership counts only in a check on a resource object, and only for a resource
 * type that has an extractor. An attribute that the extractor does not return has no value, and a
 * condition on it is not met.
 *
 * @param <T> the class of the resources this extractor reads
 */
public interface ResourceAttributeExtractor<T> {

  /** The resource type of the checks this extractor serves. */
  AuthorizationResourceType resourceType();

  /** The class of the resources this extractor reads. A resource matches if it is an instance. */
  Class<T> resourceClass();

  /**
   * Returns the values of the attributes of {@code resource}. Leave out an attribute that the
   * resource does not have.
   */
  Map<ResourceAttribute, Set<String>> attributesOf(T resource);
}
