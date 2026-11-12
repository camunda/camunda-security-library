/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static io.camunda.security.api.model.authz.ResourceAttribute.PROJECT_ID;
import static io.camunda.security.api.model.authz.ResourceAttribute.WORKSPACE_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.MembershipCondition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.authz.ResourceAccessFilter.All;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.None;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

class ResourceAccessFilterTest {

  private static final Term PAYMENTS = new Term(Set.of(), List.of(workspaceIs("payments")));

  @Test
  void anyOfWithoutTermsIsNone() {
    assertThat(ResourceAccessFilter.anyOf(List.of())).isEqualTo(new None());
  }

  @Test
  void anyOfWithATermThatMatchesEverythingIsAll() {
    assertThat(ResourceAccessFilter.anyOf(List.of(PAYMENTS, new Term(Set.of(), List.of()))))
        .isEqualTo(new All());
  }

  @Test
  void anyOfDropsDuplicateTerms() {
    assertThat(ResourceAccessFilter.anyOf(List.of(PAYMENTS, PAYMENTS)))
        .isEqualTo(new AnyOf(List.of(PAYMENTS)));
  }

  @Test
  void anyOfRecordRejectsNoTermsAndATermThatMatchesEverything() {
    assertThatThrownBy(() -> new AnyOf(List.of())).isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new AnyOf(List.of(new Term(Set.of(), List.of()))))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void termMatchesAResourceWithAnAcceptedIdThatMeetsAllConditions() {
    // given
    final var term = new Term(Set.of("d1"), List.of(workspaceIs("payments"), projectIs("p1")));

    // when / then
    assertThat(term.matches("d1", attributes("payments", "p1"))).isTrue();
    assertThat(term.matches("d2", attributes("payments", "p1"))).isFalse();
    assertThat(term.matches("d1", attributes("payments", "p2"))).isFalse();
  }

  @Test
  void termDoesNotMatchAResourceWithoutTheAttribute() {
    assertThat(PAYMENTS.matches("d1", Map.of(PROJECT_ID, Set.of("p1")))).isFalse();
    assertThat(PAYMENTS.matches("d1", Map.of(WORKSPACE_ID, Set.of()))).isFalse();
  }

  @Test
  void conditionComparesTheWildcardCharacterLiterally() {
    final var term = new Term(Set.of(), List.of(workspaceIs("*")));

    assertThat(term.matches("d1", attributes("payments", null))).isFalse();
    assertThat(term.matches("d1", attributes("*", null))).isTrue();
  }

  @Test
  void anyOfMatchesWhenOneTermMatches() {
    final var filter =
        ResourceAccessFilter.anyOf(List.of(new Term(Set.of("d9"), List.of()), PAYMENTS));

    assertThat(filter.matches("d9", attributes("billing", null))).isTrue();
    assertThat(filter.matches("d1", attributes("payments", null))).isTrue();
    assertThat(filter.matches("d1", attributes("billing", null))).isFalse();
  }

  @Test
  void translatesEachShapeIntoTheHostQuery() {
    // given
    final var filter =
        ResourceAccessFilter.anyOf(
            List.of(
                new Term(Set.of("d1", "d2"), List.of()),
                new Term(Set.of("d3"), List.of(workspaceIs("payments"), projectIs("p1")))));

    // when / then
    assertThat(filter.translate(new TextTranslator()))
        .isEqualTo(
            "any(all(id in [d1, d2]), all(id in [d3], WORKSPACE_ID = payments, PROJECT_ID = p1))");
    assertThat(new All().translate(new TextTranslator())).isEqualTo("true");
    assertThat(new None().translate(new TextTranslator())).isEqualTo("false");
  }

  private static MembershipCondition workspaceIs(final String workspace) {
    return new MembershipCondition(WORKSPACE_ID, new Operand.Equals(workspace));
  }

  private static MembershipCondition projectIs(final String project) {
    return new MembershipCondition(PROJECT_ID, new Operand.Equals(project));
  }

  private static Map<ResourceAttribute, Set<String>> attributes(
      final String workspace, final String project) {
    final var attributes = new EnumMap<ResourceAttribute, Set<String>>(ResourceAttribute.class);
    if (workspace != null) {
      attributes.put(WORKSPACE_ID, Set.of(workspace));
    }
    if (project != null) {
      attributes.put(PROJECT_ID, Set.of(project));
    }
    return attributes;
  }

  /** Writes a filter as text, so that a test can assert its whole structure. */
  private static final class TextTranslator implements ResourceAccessFilterTranslator<String> {

    @Override
    public String matchAll() {
      return "true";
    }

    @Override
    public String matchNone() {
      return "false";
    }

    @Override
    public String anyOf(final List<String> queries) {
      return "any(" + String.join(", ", queries) + ")";
    }

    @Override
    public String allOf(final List<String> queries) {
      return "all(" + String.join(", ", queries) + ")";
    }

    @Override
    public String resourceIds(final Set<String> resourceIds) {
      return "id in " + new TreeSet<>(resourceIds);
    }

    @Override
    public String attributeEquals(final ResourceAttribute attribute, final String value) {
      return attribute + " = " + value;
    }
  }
}
