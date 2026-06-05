/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth;

import static io.camunda.security.api.model.authz.AuthorizationResourceType.AUTHORIZATION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.AuthorizationResourceType.USER_TASK;
import static io.camunda.security.api.model.authz.PermissionType.READ;
import static io.camunda.security.api.model.authz.PermissionType.READ_PROCESS_DEFINITION;
import static io.camunda.security.api.model.authz.PermissionType.UPDATE_USER_TASK;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.authz.AuthorizationScope;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

class RequiredAuthorizationTest {

  private static <T> RequiredAuthorization<T> minimal() {
    return new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, null, null, false);
  }

  // ---------- compact constructor ----------

  @Test
  void compactConstructorPreservesNullResourceIds() {
    final RequiredAuthorization<Object> ra = minimal();
    assertThat(ra.resourceIds()).isNull();
  }

  @Test
  void compactConstructorPreservesNullResourcePropertyNames() {
    final RequiredAuthorization<Object> ra = minimal();
    assertThat(ra.resourcePropertyNames()).isNull();
  }

  @Test
  void compactConstructorDefensivelyCopiesResourceIds() {
    final List<String> mutableInput = new ArrayList<>(List.of("a", "b"));
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, mutableInput, null, null, null, false);

    mutableInput.add("c");

    assertThat(ra.resourceIds()).containsExactly("a", "b");
  }

  @Test
  void compactConstructorDefensivelyCopiesResourcePropertyNames() {
    final Set<String> mutableInput = new HashSet<>(Set.of("p1", "p2"));
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, mutableInput, null, false);

    mutableInput.add("p3");

    assertThat(ra.resourcePropertyNames()).containsExactlyInAnyOrder("p1", "p2");
  }

  // ---------- predicate helpers ----------

  @Test
  void hasAnyResourceIdsIsFalseWhenNull() {
    assertThat(minimal().hasAnyResourceIds()).isFalse();
  }

  @Test
  void hasAnyResourceIdsIsFalseWhenEmpty() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, List.of(), null, null, null, false);
    assertThat(ra.hasAnyResourceIds()).isFalse();
  }

  @Test
  void hasAnyResourceIdsIsTrueWhenPopulated() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, List.of("a"), null, null, null, false);
    assertThat(ra.hasAnyResourceIds()).isTrue();
  }

  @Test
  void hasAnyResourcePropertyNamesIsFalseWhenNull() {
    assertThat(minimal().hasAnyResourcePropertyNames()).isFalse();
  }

  @Test
  void hasAnyResourcePropertyNamesIsFalseWhenEmpty() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, Set.of(), null, false);
    assertThat(ra.hasAnyResourcePropertyNames()).isFalse();
  }

  @Test
  void hasAnyResourcePropertyNamesIsTrueWhenPopulated() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, Set.of("p"), null, false);
    assertThat(ra.hasAnyResourcePropertyNames()).isTrue();
  }

  @Test
  void hasAnyResourceAccessIsFalseWhenBothEmpty() {
    assertThat(minimal().hasAnyResourceAccess()).isFalse();
  }

  @Test
  void hasAnyResourceAccessIsTrueViaResourceIds() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, List.of("a"), null, null, null, false);
    assertThat(ra.hasAnyResourceAccess()).isTrue();
  }

  @Test
  void hasAnyResourceAccessIsTrueViaResourcePropertyNames() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, Set.of("p"), null, false);
    assertThat(ra.hasAnyResourceAccess()).isTrue();
  }

  // ---------- appliesTo ----------

  @Test
  void appliesToIsTrueWhenConditionIsNull() {
    final RequiredAuthorization<String> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, null, null, false);
    assertThat(ra.appliesTo("anything")).isTrue();
  }

  @Test
  void appliesToDelegatesToPredicate() {
    final Predicate<String> isHello = "hello"::equals;
    final RequiredAuthorization<String> ra =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, null, isHello, false);
    assertThat(ra.appliesTo("hello")).isTrue();
    assertThat(ra.appliesTo("world")).isFalse();
  }

  // ---------- isWildcard ----------

  @Test
  void isWildcardIsFalseWhenResourceIdsIsNull() {
    assertThat(minimal().isWildcard()).isFalse();
  }

  @Test
  void isWildcardIsFalseWhenNoWildcardPresent() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(
            AUTHORIZATION, READ, List.of("a", "b"), null, null, null, false);
    assertThat(ra.isWildcard()).isFalse();
  }

  @Test
  void isWildcardIsTrueWhenWildcardIdPresent() {
    final RequiredAuthorization<Object> ra =
        new RequiredAuthorization<>(
            AUTHORIZATION,
            READ,
            List.of("a", AuthorizationScope.WILDCARD.getResourceId()),
            null,
            null,
            null,
            false);
    assertThat(ra.isWildcard()).isTrue();
  }

  // ---------- withers ----------

  @Test
  void withResourceIdReplacesResourceIdsWithSingleton() {
    final RequiredAuthorization<Object> base = minimal();
    final RequiredAuthorization<Object> withId = base.withResourceId("id-1");

    assertThat(withId.resourceIds()).containsExactly("id-1");
    assertThat(withId.resourceType()).isEqualTo(base.resourceType());
    assertThat(withId.permissionType()).isEqualTo(base.permissionType());
    assertThat(withId.resourceIdSupplier()).isNull();
    assertThat(withId.resourcePropertyNames()).isNull();
    assertThat(withId.condition()).isNull();
    assertThat(withId.transitive()).isFalse();
  }

  @Test
  void withResourceIdsReplacesResourceIdsAndPreservesOtherFields() {
    final Function<String, String> supplier = s -> s;
    final Predicate<String> condition = "x"::equals;
    final RequiredAuthorization<String> base =
        new RequiredAuthorization<>(
            AUTHORIZATION, READ, List.of("a"), supplier, Set.of("p"), condition, true);

    final RequiredAuthorization<String> updated = base.withResourceIds(List.of("b", "c"));

    assertThat(updated.resourceIds()).containsExactly("b", "c");
    assertThat(updated.resourceIdSupplier()).isSameAs(supplier);
    assertThat(updated.resourcePropertyNames()).containsExactly("p");
    assertThat(updated.condition()).isSameAs(condition);
    assertThat(updated.transitive()).isTrue();
  }

  @Test
  void withResourceIdSupplierReplacesSupplierAndPreservesOtherFields() {
    final Function<String, String> originalSupplier = s -> "old";
    final Function<String, String> newSupplier = s -> "new";
    final RequiredAuthorization<String> base =
        new RequiredAuthorization<>(
            AUTHORIZATION, READ, List.of("a"), originalSupplier, Set.of("p"), null, true);

    final RequiredAuthorization<String> updated = base.withResourceIdSupplier(newSupplier);

    assertThat(updated.resourceIdSupplier()).isSameAs(newSupplier);
    assertThat(updated.resourceIds()).containsExactly("a");
    assertThat(updated.resourcePropertyNames()).containsExactly("p");
    assertThat(updated.transitive()).isTrue();
  }

  @Test
  void withResourcePropertyNamesReplacesAndPreservesOtherFields() {
    final RequiredAuthorization<Object> base =
        new RequiredAuthorization<>(
            AUTHORIZATION, READ, List.of("a"), null, Set.of("p1"), null, false);

    final RequiredAuthorization<Object> updated =
        base.withResourcePropertyNames(Set.of("p2", "p3"));

    assertThat(updated.resourcePropertyNames()).containsExactlyInAnyOrder("p2", "p3");
    assertThat(updated.resourceIds()).containsExactly("a");
  }

  @Test
  void withConditionReplacesConditionAndPreservesOtherFields() {
    final Predicate<String> condition = "match"::equals;
    final RequiredAuthorization<String> base =
        new RequiredAuthorization<>(AUTHORIZATION, READ, List.of("a"), null, null, null, true);

    final RequiredAuthorization<String> updated = base.withCondition(condition);

    assertThat(updated.condition()).isSameAs(condition);
    assertThat(updated.resourceIds()).containsExactly("a");
    assertThat(updated.transitive()).isTrue();
  }

  // ---------- static factories ----------

  @Test
  void withRequiredAuthorizationDelegatesResourceIdToWither() {
    final RequiredAuthorization<Object> base = minimal();
    final RequiredAuthorization<Object> updated =
        RequiredAuthorization.withRequiredAuthorization(base, "scoped-id");
    assertThat(updated.resourceIds()).containsExactly("scoped-id");
  }

  @Test
  void withRequiredAuthorizationDelegatesSupplierToWither() {
    final RequiredAuthorization<String> base =
        new RequiredAuthorization<>(AUTHORIZATION, READ, null, null, null, null, false);
    final Function<String, String> supplier = s -> "from-supplier";

    final RequiredAuthorization<String> updated =
        RequiredAuthorization.withRequiredAuthorization(base, supplier);

    assertThat(updated.resourceIdSupplier()).isSameAs(supplier);
  }

  @Test
  void ofBuildsViaBuilder() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.processDefinition().readProcessDefinition());

    assertThat(ra.resourceType()).isEqualTo(PROCESS_DEFINITION);
    assertThat(ra.permissionType()).isEqualTo(READ_PROCESS_DEFINITION);
    assertThat(ra.transitive()).isFalse();
    assertThat(ra.resourceIds()).isNull();
    assertThat(ra.resourcePropertyNames()).isNull();
  }

  // ---------- Builder ----------

  @Test
  void builderResourceTypeShortcutSetsEnum() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.userTask().updateUserTask());
    assertThat(ra.resourceType()).isEqualTo(USER_TASK);
    assertThat(ra.permissionType()).isEqualTo(UPDATE_USER_TASK);
  }

  @Test
  void builderResourceIdsSetsListWithoutCopying() {
    final List<String> ids = List.of("a", "b");
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.processDefinition().read().resourceIds(ids));
    assertThat(ra.resourceIds()).containsExactly("a", "b");
  }

  @Test
  void builderResourceIdSetsSingleton() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.processDefinition().read().resourceId("only"));
    assertThat(ra.resourceIds()).containsExactly("only");
  }

  @Test
  void builderTransitiveFlipsFlag() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.processDefinition().read().transitive());
    assertThat(ra.transitive()).isTrue();
  }

  @Test
  void builderAuthorizedByPropertyLazilyInitializesSet() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.userTask().read().authorizedByProperty("custom"));
    assertThat(ra.resourcePropertyNames()).containsExactly("custom");
  }

  @Test
  void builderAuthorizedByPropertyAccumulates() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(
            b -> b.userTask().read().authorizedByProperty("a").authorizedByProperty("b"));
    assertThat(ra.resourcePropertyNames()).containsExactlyInAnyOrder("a", "b");
  }

  @Test
  void builderAuthorizedByAssigneeUsesAssigneeConstant() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByAssignee());
    assertThat(ra.resourcePropertyNames()).containsExactly(RequiredAuthorization.PROP_ASSIGNEE);
  }

  @Test
  void builderAuthorizedByCandidateUsersUsesCandidateUsersConstant() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByCandidateUsers());
    assertThat(ra.resourcePropertyNames())
        .containsExactly(RequiredAuthorization.PROP_CANDIDATE_USERS);
  }

  @Test
  void builderAuthorizedByCandidateGroupsUsesCandidateGroupsConstant() {
    final RequiredAuthorization<Object> ra =
        RequiredAuthorization.of(b -> b.userTask().readUserTask().authorizedByCandidateGroups());
    assertThat(ra.resourcePropertyNames())
        .containsExactly(RequiredAuthorization.PROP_CANDIDATE_GROUPS);
  }

  @Test
  void builderResourceIdSupplierSetsSupplier() {
    final Function<String, String> supplier = s -> s;
    final RequiredAuthorization<String> ra =
        RequiredAuthorization.<String>of(
            b -> b.processDefinition().read().resourceIdSupplier(supplier));
    assertThat(ra.resourceIdSupplier()).isSameAs(supplier);
  }

  @Test
  void builderConditionSetsCondition() {
    final Predicate<String> cond = "x"::equals;
    final RequiredAuthorization<String> ra =
        RequiredAuthorization.<String>of(b -> b.processDefinition().read().condition(cond));
    assertThat(ra.condition()).isSameAs(cond);
  }

  // `or()` is a no-op fluent connector. It does NOT compose conditions: a subsequent
  // condition(y) overwrites a prior condition(x). This test documents and locks that behaviour.
  @Test
  void builderOrIsNoOpAndConditionIsSetOnly() {
    final Predicate<String> first = "first"::equals;
    final Predicate<String> second = "second"::equals;

    final RequiredAuthorization<String> ra =
        RequiredAuthorization.<String>of(
            b -> b.processDefinition().read().condition(first).or().condition(second));

    assertThat(ra.condition()).isSameAs(second);
    assertThat(ra.appliesTo("second")).isTrue();
    assertThat(ra.appliesTo("first")).isFalse();
  }
}
