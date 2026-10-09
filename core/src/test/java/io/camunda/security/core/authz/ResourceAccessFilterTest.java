/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.Condition;
import io.camunda.security.api.model.authz.Operand;
import io.camunda.security.api.model.authz.PrincipalAttribute;
import io.camunda.security.api.model.authz.ResourceAttribute;
import io.camunda.security.core.authz.ResourceAccessFilter.All;
import io.camunda.security.core.authz.ResourceAccessFilter.AnyOf;
import io.camunda.security.core.authz.ResourceAccessFilter.None;
import io.camunda.security.core.authz.ResourceAccessFilter.Term;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

class ResourceAccessFilterTest {

  private static Condition workspaceIn(final String... values) {
    return new Condition(ResourceAttribute.WORKSPACE, new Operand.Values(Set.of(values)));
  }

  private static Map<ResourceAttribute, Set<String>> inWorkspace(final String... values) {
    return Map.of(ResourceAttribute.WORKSPACE, Set.of(values));
  }

  @Test
  void allMatchesEverythingAndNoneMatchesNothing() {
    assertThat(new All().matches("x", Map.of())).isTrue();
    assertThat(new None().matches("x", inWorkspace("w1"))).isFalse();
  }

  @Test
  void termWithIdsMatchesOnlyThoseIds() {
    final var filter = new AnyOf(List.of(new Term(Set.of("pa1", "pa2"), List.of())));

    assertThat(filter.matches("pa1", Map.of())).isTrue();
    assertThat(filter.matches("pa3", Map.of())).isFalse();
  }

  @Test
  void termWithConditionsRequiresAllOfThemToOverlap() {
    final var filter =
        new AnyOf(
            List.of(
                new Term(
                    Set.of(),
                    List.of(
                        workspaceIn("w1", "w2"),
                        new Condition(
                            ResourceAttribute.ASSIGNEE, new Operand.Values(Set.of("alice")))))));

    assertThat(
            filter.matches(
                "x",
                Map.of(
                    ResourceAttribute.WORKSPACE, Set.of("w2", "w9"),
                    ResourceAttribute.ASSIGNEE, Set.of("alice"))))
        .isTrue();
    assertThat(filter.matches("x", inWorkspace("w2"))).isFalse();
    assertThat(filter.matches("x", inWorkspace("w9"))).isFalse();
  }

  @Test
  void termWithIdsAndConditionsRequiresBoth() {
    final var filter = new AnyOf(List.of(new Term(Set.of("pa1"), List.of(workspaceIn("w1")))));

    assertThat(filter.matches("pa1", inWorkspace("w1"))).isTrue();
    assertThat(filter.matches("pa1", inWorkspace("w2"))).isFalse();
    assertThat(filter.matches("pa2", inWorkspace("w1"))).isFalse();
  }

  @Test
  void anyOfMatchesWhenOneTermMatches() {
    final var filter =
        new AnyOf(
            List.of(
                new Term(Set.of(), List.of(workspaceIn("w1"))),
                new Term(Set.of("pa9"), List.of())));

    assertThat(filter.matches("pa1", inWorkspace("w1"))).isTrue();
    assertThat(filter.matches("pa9", inWorkspace("w2"))).isTrue();
    assertThat(filter.matches("pa1", inWorkspace("w2"))).isFalse();
  }

  @Test
  void aConditionOnAnAttributeTheResourceLacksIsNotMet() {
    final var filter = new AnyOf(List.of(new Term(Set.of(), List.of(workspaceIn("w1")))));

    assertThat(filter.matches("pa1", Map.of())).isFalse();
    assertThat(filter.matches("pa1", Map.of(ResourceAttribute.WORKSPACE, Set.of()))).isFalse();
  }

  @Test
  void termRejectsConditionsThatAreNotResolvedToValues() {
    final var principalCondition =
        new Condition(
            ResourceAttribute.ASSIGNEE, new Operand.Principal(PrincipalAttribute.USERNAME));

    assertThatThrownBy(() -> new Term(Set.of(), List.of(principalCondition)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("ASSIGNEE");
  }

  @Test
  void termNormalizesMissingIdsAndConditionsAndKnowsWhenItIsUnrestricted() {
    assertThat(new Term(null, null).isUnrestricted()).isTrue();
    assertThat(new Term(Set.of("pa1"), null).isUnrestricted()).isFalse();
    assertThat(new Term(null, List.of(workspaceIn("w1"))).isUnrestricted()).isFalse();
  }

  @Test
  void anyOfRequiresAtLeastOneTerm() {
    assertThatThrownBy(() -> new AnyOf(List.of())).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void translateMapsTheStructureOntoTheTranslator() {
    final var filter =
        new AnyOf(
            List.of(
                new Term(Set.of("pa1"), List.of(workspaceIn("w1"))),
                new Term(Set.of(), List.of(workspaceIn("w2"))),
                new Term(Set.of("pa3"), List.of())));

    final var translated = filter.translate(new StringTranslator());

    assertThat(translated)
        .isEqualTo("any(all(ids[pa1],WORKSPACE[w1]),all(WORKSPACE[w2]),all(ids[pa3]))");
  }

  @Test
  void translateMapsAllAndNone() {
    assertThat(new All().translate(new StringTranslator())).isEqualTo("all");
    assertThat(new None().translate(new StringTranslator())).isEqualTo("none");
  }

  @Test
  void translateMapsAnUnrestrictedTermToMatchAll() {
    final var filter = new AnyOf(List.of(new Term(Set.of(), List.of())));

    assertThat(filter.translate(new StringTranslator())).isEqualTo("any(all)");
  }

  private static final class StringTranslator implements ResourceAccessFilterTranslator<String> {

    @Override
    public String matchAll() {
      return "all";
    }

    @Override
    public String matchNone() {
      return "none";
    }

    @Override
    public String anyOf(final List<String> alternatives) {
      return "any(" + String.join(",", alternatives) + ")";
    }

    @Override
    public String allOf(final List<String> parts) {
      return "all(" + String.join(",", parts) + ")";
    }

    @Override
    public String resourceIds(final Set<String> resourceIds) {
      return "ids" + new TreeSet<>(resourceIds);
    }

    @Override
    public String condition(final ResourceAttribute attribute, final Set<String> values) {
      return attribute + "" + new TreeSet<>(values);
    }
  }
}
