/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class MappingRuleMatcherTest {

  private record MappingRuleEntity(String mappingRuleId, String claimName, String claimValue)
      implements MappingRuleMatcher.MappingRule {}

  /** Tests for the {@link MappingRuleMatcher#matchingRules(Stream, Map)} method. */
  @Nested
  class MatchingRulesTest {

    @Test
    @DisplayName("returns empty when claims is null")
    void returnsEmptyWhenClaimsNull() {
      // given
      final var rules = List.of(new MappingRuleEntity("r1", "$.sub", "alice"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), null).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("returns empty when no mapping rules provided")
    void returnsEmptyWhenNoRules() {
      // given
      final Map<String, Object> claims = Map.of("sub", "alice");

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(Stream.<MappingRuleEntity>empty(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("matches simple scalar claim and filters non-matching")
    void matchesSimpleScalar() {
      // given
      final Map<String, Object> claims = Map.of("sub", "alice");
      final var rules =
          List.of(
              new MappingRuleEntity("match", "$.sub", "alice"),
              new MappingRuleEntity("nope", "$.sub", "bob"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("match");
    }

    @Test
    @DisplayName("does not match when JSONPath points to missing leaf")
    void doesNotMatchMissingLeaf() {
      // given
      final Map<String, Object> claims = Map.of("sub", "alice");
      final var rules = List.of(new MappingRuleEntity("r1", "$.email", "alice"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("does not match when types differ")
    void doesNotMatchTypeMismatch() {
      // given
      final Map<String, Object> claims = Map.of("age", 30); // Integer value
      final var rules = List.of(new MappingRuleEntity("r1", "$.age", "30")); // String expected

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("matches when collection claim contains expected value")
    void matchesCollectionContains() {
      // given
      final Map<String, Object> claims = Map.of("roles", List.of("admin", "operator"));
      final var rules =
          List.of(
              new MappingRuleEntity("admin", "$.roles", "admin"),
              new MappingRuleEntity("developer", "$.roles", "developer"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("admin");
    }

    @Test
    @DisplayName("matches nested path inside object")
    void matchesNestedPath() {
      // given
      final Map<String, Object> claims =
          Map.of("realm", Map.of("roles", List.of("admin", "operator")));
      final var rules = List.of(new MappingRuleEntity("operator", "$.realm.roles", "operator"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("operator");
    }

    @Test
    @DisplayName("filters mixed results preserving order of matching rules")
    void filtersMixedResultsPreservingOrder() {
      // given
      final Map<String, Object> claims =
          Map.of(
              "sub", "alice",
              "roles", List.of("admin", "developer"),
              "realm", Map.of("region", "eu"));
      final var rules =
          List.of(
              new MappingRuleEntity("r1", "$.sub", "alice"),
              new MappingRuleEntity("r2", "$.sub", "bob"),
              new MappingRuleEntity("r3", "$.roles", "admin"),
              new MappingRuleEntity("r4", "$.realm.region", "us"),
              new MappingRuleEntity("r5", "$.realm.region", "eu"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result)
          .extracting(MappingRuleEntity::mappingRuleId)
          .containsExactly("r1", "r3", "r5");
    }

    @Test
    @DisplayName("invalid JSONPath expression is ignored (not matching)")
    void invalidJsonPathIgnored() {
      // given
      final Map<String, Object> claims = Map.of("sub", "alice");
      final var rules = List.of(new MappingRuleEntity("bad", "$.sub['", "alice")); // invalid path

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("collection claim where expected value not present")
    void collectionClaimValueNotPresent() {
      // given
      final Map<String, Object> claims = Map.of("roles", List.of("user", "viewer"));
      final var rules = List.of(new MappingRuleEntity("admin", "$.roles", "admin"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    /**
     * This test does not actually test new behavior, but covers the code path where the same
     * expression is used multiple times, exercising the caching logic. It's not strictly necessary,
     * but nice to have coverage of the cache.
     */
    @Test
    @DisplayName("multiple rules share same expression (cache exercise)")
    void multipleRulesSameExpression() {
      // given
      final Map<String, Object> claims = Map.of("dept", "sales");
      final var rules =
          List.of(
              new MappingRuleEntity("sales", "$.dept", "sales"),
              new MappingRuleEntity("engineering", "$.dept", "engineering"),
              new MappingRuleEntity("support", "$.dept", "support"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("sales");
    }

    @Test
    @DisplayName("plain claim name (no $-prefix) is sanitized to a JSONPath and matches")
    void plainClaimNameIsSanitizedAndMatches() {
      // given
      final Map<String, Object> claims = Map.of("sub", "alice");
      final var rules = List.of(new MappingRuleEntity("r1", "sub", "alice"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("r1");
    }

    @Test
    @DisplayName("rule with null claimValue does not throw and does not match a non-null claim")
    void nullClaimValueIsHandledSafely() {
      // given — claimValue() is null; the matcher must not NPE on .equals() and must return no
      // match because the resolved claim is a non-null string.
      final Map<String, Object> claims = Map.of("sub", "alice");
      final var rules = List.of(new MappingRuleEntity("r1", "$.sub", null));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("plain claim name containing special characters is escaped and matches")
    void plainClaimNameWithSpecialCharsIsEscapedAndMatches() {
      // given — claim name contains a single quote and a backslash, both of which must be
      // escaped to produce a valid JSONPath ($['weird\\'key']).
      final Map<String, Object> claims = Map.of("weird\\'key", "value");
      final var rules = List.of(new MappingRuleEntity("r1", "weird\\'key", "value"));

      // when
      final List<MappingRuleEntity> result =
          MappingRuleMatcher.matchingRules(rules.stream(), claims).toList();

      // then
      assertThat(result).extracting(MappingRuleEntity::mappingRuleId).containsExactly("r1");
    }
  }
}
