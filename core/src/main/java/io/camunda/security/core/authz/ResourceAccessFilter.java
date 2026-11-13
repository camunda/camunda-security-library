/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Describes which resources of one type a principal may access with one permission, so that a host
 * can turn it into a query of its own (ADR-0041). {@link ConditionalResourceAccessProvider} says
 * when a list filtered this way agrees with the single check.
 *
 * <ul>
 *   <li>{@link All}: every resource.
 *   <li>{@link None}: no resource.
 *   <li>{@link AnyOf}: the resources that match at least one {@link Term}.
 * </ul>
 *
 * <p>A host turns a filter into its query model with {@link
 * #translate(ResourceAccessFilterTranslator)}, and decides there how the resource ID and each
 * {@link ResourceAttribute} map to its storage. {@link #matches(String, Map)} applies a filter to
 * one resource.
 */
public sealed interface ResourceAccessFilter {

  /**
   * Returns the filter for the resources that match at least one of {@code terms}: {@link None} if
   * there are no terms, {@link All} if a term matches every resource, and {@link AnyOf} otherwise.
   */
  static ResourceAccessFilter anyOf(final Collection<Term> terms) {
    if (terms.isEmpty()) {
      return new None();
    }
    if (terms.stream().anyMatch(Term::matchesAll)) {
      return new All();
    }
    return new AnyOf(List.copyOf(new LinkedHashSet<>(terms)));
  }

  /**
   * Returns whether this filter matches a resource.
   *
   * @param resourceId the ID of the resource
   * @param attributes the attribute values of the resource
   */
  default boolean matches(
      final String resourceId, final Map<ResourceAttribute, Set<String>> attributes) {
    return switch (this) {
      case All all -> true;
      case None none -> false;
      case AnyOf anyOf -> anyOf.terms().stream().anyMatch(t -> t.matches(resourceId, attributes));
    };
  }

  /** Translates this filter into the query model of a host. */
  default <R> R translate(final ResourceAccessFilterTranslator<R> translator) {
    return switch (this) {
      case All all -> translator.matchAll();
      case None none -> translator.matchNone();
      case AnyOf anyOf ->
          translator.anyOf(anyOf.terms().stream().map(t -> t.translate(translator)).toList());
    };
  }

  /** Matches every resource. */
  record All() implements ResourceAccessFilter {}

  /** Matches no resource. */
  record None() implements ResourceAccessFilter {}

  /**
   * Matches the resources that match at least one term. Use {@link
   * ResourceAccessFilter#anyOf(Collection)}, which returns {@link None} or {@link All} where they
   * apply.
   *
   * @param terms the terms; not empty, and none of them matches every resource
   */
  record AnyOf(List<Term> terms) implements ResourceAccessFilter {

    public AnyOf {
      Objects.requireNonNull(terms, "terms");
      terms = List.copyOf(terms);
      if (terms.isEmpty()) {
        throw new IllegalArgumentException("AnyOf needs at least one term; use None instead.");
      }
      if (terms.stream().anyMatch(Term::matchesAll)) {
        throw new IllegalArgumentException(
            "AnyOf must not contain a term that matches every resource; use All instead.");
      }
    }
  }

  /**
   * Matches the resources whose ID is in {@code resourceIds} and that meet all {@code conditions}.
   *
   * @param resourceIds the accepted resource IDs; empty means that the ID is not restricted
   * @param conditions the conditions on resource attributes, all of which must be met
   */
  record Term(Set<String> resourceIds, List<MembershipCondition> conditions) {

    public Term {
      resourceIds = Set.copyOf(Objects.requireNonNull(resourceIds, "resourceIds"));
      conditions = List.copyOf(Objects.requireNonNull(conditions, "conditions"));
    }

    /** Returns whether this term matches every resource. */
    public boolean matchesAll() {
      return resourceIds.isEmpty() && conditions.isEmpty();
    }

    boolean matches(final String resourceId, final Map<ResourceAttribute, Set<String>> attributes) {
      return (resourceIds.isEmpty() || resourceIds.contains(resourceId))
          && ResourceConditions.allMet(conditions, attributes);
    }

    <R> R translate(final ResourceAccessFilterTranslator<R> translator) {
      final List<R> parts = new ArrayList<>();
      if (!resourceIds.isEmpty()) {
        parts.add(translator.resourceIds(resourceIds));
      }
      for (final MembershipCondition condition : conditions) {
        parts.add(
            switch (condition.operand()) {
              case Operand.Equals equals ->
                  translator.attributeEquals(condition.attribute(), equals.value());
            });
      }
      return translator.allOf(parts);
    }
  }
}
