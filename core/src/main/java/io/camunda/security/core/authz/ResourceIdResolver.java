/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.core.auth.RequiredAuthorization;

/**
 * Derives the ID of the single resource a check on a resource object applies to. Shared by every
 * evaluation that takes the resource object, so that they agree on which ID a resource is checked
 * under.
 *
 * <p>Stricter than a lookup that falls back to explicit IDs: the {@link
 * RequiredAuthorization#resourceIdSupplier() resourceIdSupplier} is required, explicit {@link
 * RequiredAuthorization#resourceIds() resourceIds} are rejected, and there is no single-ID
 * fallback. The ID may depend on the permission being checked, which is why the requirement, not
 * the resource type, provides it.
 */
public final class ResourceIdResolver {

  private ResourceIdResolver() {}

  /**
   * Returns the ID that {@code authorization}'s {@code resourceIdSupplier} derives from {@code
   * resource}.
   *
   * @throws IllegalArgumentException if {@code authorization} has no supplier, also carries
   *     explicit resource IDs, or the supplier returns no ID
   */
  public static <T> String resolveResourceId(
      final RequiredAuthorization<T> authorization, final T resource) {
    if (authorization.hasAnyResourceIds()) {
      throw new IllegalArgumentException(
          "A check on resource type "
              + authorization.resourceType()
              + " takes its resource ID from the resource and does not accept explicit resource IDs");
    }
    final var supplier = authorization.resourceIdSupplier();
    if (supplier == null) {
      throw new IllegalArgumentException(
          "A check on resource type "
              + authorization.resourceType()
              + " requires a resourceIdSupplier to derive the resource ID from the resource");
    }
    final String resourceId = supplier.apply(resource);
    if (resourceId == null || resourceId.isEmpty()) {
      throw new IllegalArgumentException(
          "The resourceIdSupplier for resource type "
              + authorization.resourceType()
              + " returned no resource ID");
    }
    return resourceId;
  }
}
