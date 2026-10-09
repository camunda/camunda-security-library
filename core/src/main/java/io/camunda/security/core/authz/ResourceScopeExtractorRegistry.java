/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.context.ResourceScopeExtractor;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Holds {@link ResourceScopeExtractor} instances keyed by their {@link
 * ResourceScopeExtractor#resourceType() resourceType}, with several extractors per resource type
 * distinguished by {@link ResourceScopeExtractor#resourceClass() resourceClass}.
 *
 * <p>The {@link #findExtractor} method performs an unchecked cast from the wildcard type to the
 * caller-specified {@code T}; it is safe because the extractor is only returned for resources that
 * are instances of its resource class. Duplicate (resource type, resource class) pairs are rejected
 * at construction time.
 */
public final class ResourceScopeExtractorRegistry {

  private final Map<AuthorizationResourceType, List<ResourceScopeExtractor<?>>> extractors;

  public ResourceScopeExtractorRegistry(
      final List<? extends ResourceScopeExtractor<?>> extractors) {
    final var seen = new HashSet<List<Object>>();
    for (final var extractor : extractors) {
      if (!seen.add(List.of(extractor.resourceType(), extractor.resourceClass()))) {
        throw new IllegalStateException(
            "Duplicate ResourceScopeExtractor for resource type "
                + extractor.resourceType()
                + " and resource class "
                + extractor.resourceClass().getName());
      }
    }
    this.extractors =
        extractors.stream()
            .collect(
                Collectors.groupingBy(
                    ResourceScopeExtractor::resourceType,
                    Collectors.<ResourceScopeExtractor<?>>toUnmodifiableList()));
  }

  /**
   * Returns the extractor for {@code resourceType} whose resource class accepts {@code resource},
   * cast to the expected resource type {@code T}. Returns {@link Optional#empty()} when no
   * extractor is registered for {@code resourceType}.
   *
   * @throws NullPointerException if extractors are registered for {@code resourceType} and {@code
   *     resource} is {@code null}
   * @throws IllegalArgumentException if extractors are registered for {@code resourceType} but none
   *     accepts {@code resource}
   */
  @SuppressWarnings("unchecked")
  public <T> Optional<ResourceScopeExtractor<T>> findExtractor(
      final AuthorizationResourceType resourceType, final Object resource) {
    final var candidates = extractors.get(resourceType);
    if (candidates == null) {
      return Optional.empty();
    }
    Objects.requireNonNull(resource, "resource");
    final var match =
        candidates.stream()
            .filter(extractor -> extractor.resourceClass().isInstance(resource))
            .findFirst();
    if (match.isEmpty()) {
      throw new IllegalArgumentException(
          "No ResourceScopeExtractor for resource type "
              + resourceType
              + " accepts resource of class "
              + resource.getClass().getName());
    }
    return Optional.of((ResourceScopeExtractor<T>) match.get());
  }
}
