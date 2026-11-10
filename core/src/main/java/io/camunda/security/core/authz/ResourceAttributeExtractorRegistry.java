/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Holds {@link ResourceAttributeExtractor} instances by {@link
 * ResourceAttributeExtractor#resourceType() resource type}. One resource type can have several
 * extractors with different {@link ResourceAttributeExtractor#resourceClass() resource classes}.
 *
 * <p>The constructor rejects two extractors for the same resource type and resource class. The
 * {@link #findMatching} method makes an unchecked cast to the {@code T} of the caller. This is safe
 * because the extractor accepts the resource only if the resource is an instance of its class.
 */
public final class ResourceAttributeExtractorRegistry {

  private final Map<AuthorizationResourceType, List<ResourceAttributeExtractor<?>>> extractors;

  public ResourceAttributeExtractorRegistry(
      final List<? extends ResourceAttributeExtractor<?>> extractors) {
    final var registered = new HashSet<List<Object>>();
    for (final ResourceAttributeExtractor<?> extractor : extractors) {
      final var resourceType = Objects.requireNonNull(extractor.resourceType(), "resourceType");
      final var resourceClass = Objects.requireNonNull(extractor.resourceClass(), "resourceClass");
      if (!registered.add(List.of(resourceType, resourceClass))) {
        throw new IllegalStateException(
            "Duplicate ResourceAttributeExtractor for resource type %s and resource class %s"
                .formatted(resourceType, resourceClass.getName()));
      }
    }
    this.extractors =
        extractors.stream()
            .collect(
                Collectors.groupingBy(
                    ResourceAttributeExtractor::resourceType,
                    Collectors.<ResourceAttributeExtractor<?>>toUnmodifiableList()));
  }

  /** Returns whether an extractor is registered for {@code resourceType}. */
  public boolean hasExtractorsFor(final AuthorizationResourceType resourceType) {
    return extractors.containsKey(resourceType);
  }

  /**
   * Returns the extractor for {@code resourceType} whose resource class accepts {@code resource},
   * or {@link Optional#empty()} when there is none.
   */
  @SuppressWarnings("unchecked")
  public <T> Optional<ResourceAttributeExtractor<T>> findMatching(
      final AuthorizationResourceType resourceType, final T resource) {
    return extractors.getOrDefault(resourceType, List.of()).stream()
        .filter(extractor -> extractor.resourceClass().isInstance(resource))
        .findFirst()
        .map(extractor -> (ResourceAttributeExtractor<T>) extractor);
  }
}
