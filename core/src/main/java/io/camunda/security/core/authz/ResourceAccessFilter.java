/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A declarative description of the resources of one type that a principal may access with one
 * permission, for hosts that translate it into a query. A resource is accessible if any {@link
 * Term} of an {@link AnyOf} matches it. The terms are derived from unconditional grants, grants of
 * conditional role memberships, and principal-derived property grants; the filter only carries
 * concrete values.
 *
 * <p>Hosts translate a filter with {@link #translate(ResourceAccessFilterTranslator)}, which leaves
 * the mapping of {@link ResourceAttribute}s to storage to them. {@link #matches(String, Map)}
 * evaluates a filter against a single resource.
 */
public sealed interface ResourceAccessFilter {

  /**
   * Evaluates this filter against a resource.
   *
   * @param resourceId the ID of the resource
   * @param attributes the attribute values of the resource
   */
  default boolean matches(
      final String resourceId, final Map<ResourceAttribute, Set<String>> attributes) {
    return switch (this) {
      case final All all -> true;
      case final None none -> false;
      case final AnyOf anyOf ->
          anyOf.terms().stream().anyMatch(term -> term.matches(resourceId, attributes));
    };
  }

  /** Translates this filter into the query model of a host. */
  default <R> R translate(final ResourceAccessFilterTranslator<R> translator) {
    return switch (this) {
      case final All all -> translator.matchAll();
      case final None none -> translator.matchNone();
      case final AnyOf anyOf ->
          translator.anyOf(
              anyOf.terms().stream().map(term -> translateTerm(term, translator)).toList());
    };
  }

  private static <R> R translateTerm(
      final Term term, final ResourceAccessFilterTranslator<R> translator) {
    final List<R> parts = new ArrayList<>();
    if (!term.resourceIds().isEmpty()) {
      parts.add(translator.resourceIds(term.resourceIds()));
    }
    for (final Condition condition : term.conditions()) {
      parts.add(
          translator.condition(
              condition.attribute(), ((Operand.Values) condition.operand()).values()));
    }
    return parts.isEmpty() ? translator.matchAll() : translator.allOf(parts);
  }

  /** Matches every resource. */
  record All() implements ResourceAccessFilter {}

  /** Matches no resource. */
  record None() implements ResourceAccessFilter {}

  /**
   * Matches the resources that match at least one term.
   *
   * @param terms the terms; not empty
   */
  record AnyOf(List<Term> terms) implements ResourceAccessFilter {

    public AnyOf {
      Objects.requireNonNull(terms, "terms");
      terms = List.copyOf(terms);
      if (terms.isEmpty()) {
        throw new IllegalArgumentException("AnyOf requires at least one term");
      }
    }
  }

  /**
   * Matches the resources whose ID is one of {@code resourceIds}, if there are any, and that meet
   * all {@code conditions}.
   *
   * @param resourceIds the accepted resource IDs; empty means the ID is not restricted
   * @param conditions conditions on resource attributes, all with {@link Operand.Values} operands
   */
  record Term(Set<String> resourceIds, List<Condition> conditions) {

    public Term {
      resourceIds = resourceIds == null ? Set.of() : Set.copyOf(resourceIds);
      conditions = conditions == null ? List.of() : List.copyOf(conditions);
      for (final Condition condition : conditions) {
        if (!(condition.operand() instanceof Operand.Values)) {
          throw new IllegalArgumentException(
              "Conditions of a term must be resolved to values, but the condition on "
                  + condition.attribute()
                  + " has operand "
                  + condition.operand());
        }
      }
    }

    /** Whether the term matches every resource. */
    public boolean isUnrestricted() {
      return resourceIds.isEmpty() && conditions.isEmpty();
    }

    boolean matches(final String resourceId, final Map<ResourceAttribute, Set<String>> attributes) {
      return (resourceIds.isEmpty() || resourceIds.contains(resourceId))
          && ResourceConditions.allMet(conditions, attributes, null);
    }
  }
}
