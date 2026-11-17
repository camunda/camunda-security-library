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
import java.util.ArrayList;
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
 * <p>The constructor rejects two extractors of the same resource type whose classes overlap, that
 * is, one class is the same as, or a subtype of, the other. If more than one extractor still
 * accepts a resource, {@link #findMatching} finds none. The {@link #findMatching} method makes an
 * unchecked cast to the {@code T} of the caller. This is safe for the given resource, because the
 * extractor accepts it only if it is an instance of the extractor's class.
 */
public final class ResourceAttributeExtractorRegistry {

  private final Map<AuthorizationResourceType, List<ResourceAttributeExtractor<?>>> extractors;

  public ResourceAttributeExtractorRegistry(
      final List<? extends ResourceAttributeExtractor<?>> extractors) {
    final var registered = new ArrayList<ResourceAttributeExtractor<?>>();
    for (final ResourceAttributeExtractor<?> extractor : extractors) {
      Objects.requireNonNull(extractor.resourceType(), "resourceType");
      Objects.requireNonNull(extractor.resourceClass(), "resourceClass");
      registered.stream()
          .filter(other -> overlap(other, extractor))
          .findFirst()
          .ifPresent(
              other -> {
                throw new IllegalStateException(
                    ("Overlapping ResourceAttributeExtractors for resource type %s: resource"
                            + " classes %s and %s")
                        .formatted(
                            extractor.resourceType(),
                            other.resourceClass().getName(),
                            extractor.resourceClass().getName()));
              });
      registered.add(extractor);
    }
    this.extractors =
        extractors.stream()
            .collect(
                Collectors.groupingBy(
                    ResourceAttributeExtractor::resourceType,
                    Collectors.<ResourceAttributeExtractor<?>>toUnmodifiableList()));
  }

  private static boolean overlap(
      final ResourceAttributeExtractor<?> first, final ResourceAttributeExtractor<?> second) {
    return first.resourceType() == second.resourceType()
        && (first.resourceClass().isAssignableFrom(second.resourceClass())
            || second.resourceClass().isAssignableFrom(first.resourceClass()));
  }

  /** Returns whether an extractor is registered for {@code resourceType}. */
  public boolean hasExtractorsFor(final AuthorizationResourceType resourceType) {
    return extractors.containsKey(resourceType);
  }

  /**
   * Returns the extractor for {@code resourceType} whose resource class accepts {@code resource},
   * or {@link Optional#empty()} when there is none. Also returns {@link Optional#empty()} when more
   * than one extractor accepts it: this can happen when the classes are unrelated interfaces that
   * the resource both implements.
   */
  @SuppressWarnings("unchecked")
  public <T> Optional<ResourceAttributeExtractor<T>> findMatching(
      final AuthorizationResourceType resourceType, final T resource) {
    final var matching =
        extractors.getOrDefault(resourceType, List.of()).stream()
            .filter(extractor -> extractor.resourceClass().isInstance(resource))
            .limit(2)
            .toList();
    return matching.size() == 1
        ? Optional.of((ResourceAttributeExtractor<T>) matching.getFirst())
        : Optional.empty();
  }
}
