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
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Holds {@link ResourceAttributeExtractor} instances keyed by their {@link
 * ResourceAttributeExtractor#resourceType() resourceType}, with several extractors per resource
 * type distinguished by {@link ResourceAttributeExtractor#resourceClass() resourceClass}.
 *
 * <p>Duplicate (resource type, resource class) pairs are rejected at construction time, as are
 * extractors that provide no attributes or attributes their resource type does not declare. The
 * attributes an extractor returns are checked against its provided attributes when they are read.
 * Null and empty values are removed, so they count as absent.
 */
public final class ResourceAttributeExtractorRegistry {

  private final Map<AuthorizationResourceType, List<ResourceAttributeExtractor<?>>> extractors;

  public ResourceAttributeExtractorRegistry(
      final List<? extends ResourceAttributeExtractor<?>> extractors) {
    final var seen = new HashSet<List<Object>>();
    for (final var extractor : extractors) {
      validateProvidedAttributes(extractor);
      if (!seen.add(List.of(extractor.resourceType(), extractor.resourceClass()))) {
        throw new IllegalStateException(
            "Duplicate ResourceAttributeExtractor for resource type "
                + extractor.resourceType()
                + " and resource class "
                + extractor.resourceClass().getName());
      }
    }
    this.extractors =
        extractors.stream()
            .collect(
                Collectors.groupingBy(
                    ResourceAttributeExtractor::resourceType,
                    Collectors.<ResourceAttributeExtractor<?>>toUnmodifiableList()));
  }

  private static void validateProvidedAttributes(final ResourceAttributeExtractor<?> extractor) {
    final var provided = extractor.providedAttributes();
    if (provided == null || provided.isEmpty()) {
      throw new IllegalStateException(
          "ResourceAttributeExtractor for resource type "
              + extractor.resourceType()
              + " and resource class "
              + extractor.resourceClass().getName()
              + " provides no attributes");
    }
    final var undeclared = new HashSet<>(provided);
    undeclared.removeAll(extractor.resourceType().getSupportedAttributes());
    if (!undeclared.isEmpty()) {
      throw new IllegalStateException(
          "ResourceAttributeExtractor for resource type "
              + extractor.resourceType()
              + " and resource class "
              + extractor.resourceClass().getName()
              + " provides attributes that the resource type does not declare: "
              + undeclared);
    }
  }

  /** Returns whether any extractor is registered for {@code resourceType}. */
  public boolean hasExtractorsFor(final AuthorizationResourceType resourceType) {
    return extractors.containsKey(resourceType);
  }

  /**
   * Returns the extractor for {@code resourceType} whose resource class accepts {@code resource},
   * or {@link Optional#empty()} if there is none.
   */
  @SuppressWarnings("unchecked")
  public <T> Optional<ResourceAttributeExtractor<T>> findMatching(
      final AuthorizationResourceType resourceType, final Object resource) {
    return extractors.getOrDefault(resourceType, List.of()).stream()
        .filter(extractor -> extractor.resourceClass().isInstance(resource))
        .findFirst()
        .map(extractor -> (ResourceAttributeExtractor<T>) extractor);
  }

  /**
   * Returns the attribute values of {@code resource}, provided by the extractor registered for
   * {@code resourceType} and the class of {@code resource}.
   *
   * @throws NullPointerException if {@code resource} is {@code null}
   * @throws IllegalArgumentException if no extractor registered for {@code resourceType} accepts
   *     {@code resource}
   * @throws IllegalStateException if the extractor returns an attribute outside its provided
   *     attributes
   */
  public <T> Map<ResourceAttribute, Set<String>> attributesOf(
      final AuthorizationResourceType resourceType, final T resource) {
    Objects.requireNonNull(resource, "resource");
    final ResourceAttributeExtractor<T> extractor =
        this.<T>findMatching(resourceType, resource)
            .orElseThrow(
                () ->
                    new IllegalArgumentException(
                        "No ResourceAttributeExtractor for resource type "
                            + resourceType
                            + " accepts resource of class "
                            + resource.getClass().getName()));
    final var attributes = extractor.attributesOf(resource);
    if (attributes == null) {
      return Map.of();
    }
    final var unprovided = new HashSet<>(attributes.keySet());
    unprovided.removeAll(extractor.providedAttributes());
    if (!unprovided.isEmpty()) {
      throw new IllegalStateException(
          "ResourceAttributeExtractor for resource type "
              + resourceType
              + " and resource class "
              + extractor.resourceClass().getName()
              + " returned attributes it does not provide "
              + unprovided);
    }
    return withoutAbsentValues(attributes);
  }

  private static Map<ResourceAttribute, Set<String>> withoutAbsentValues(
      final Map<ResourceAttribute, Set<String>> attributes) {
    final var cleaned = new EnumMap<ResourceAttribute, Set<String>>(ResourceAttribute.class);
    attributes.forEach(
        (attribute, values) -> {
          if (values == null) {
            return;
          }
          final var present =
              values.stream()
                  .filter(value -> value != null && !value.isEmpty())
                  .collect(Collectors.toUnmodifiableSet());
          if (!present.isEmpty()) {
            cleaned.put(attribute, present);
          }
        });
    return Collections.unmodifiableMap(cleaned);
  }

  /** The (resource type, resource class) pairs that have an extractor. */
  Set<List<Object>> registrations() {
    return extractors.values().stream()
        .flatMap(List::stream)
        .map(extractor -> List.<Object>of(extractor.resourceType(), extractor.resourceClass()))
        .collect(Collectors.toUnmodifiableSet());
  }
}
