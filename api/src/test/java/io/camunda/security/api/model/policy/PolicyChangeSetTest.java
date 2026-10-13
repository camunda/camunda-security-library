/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.authz.AuthorizationOwnerType;
import io.camunda.security.api.model.authz.AuthorizationResourceMatcher;
import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.EntityType;
import io.camunda.security.api.model.authz.PermissionType;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyChangeSetTest {

  private static final PolicyMembership MEMBERSHIP =
      new PolicyMembership(PolicyMembershipTarget.ROLE, "r1", EntityType.USER, "u1");
  private static final PolicyAuthorizationKey KEY =
      new PolicyAuthorizationKey(
          AuthorizationOwnerType.ROLE,
          "r1",
          AuthorizationResourceType.RESOURCE,
          AuthorizationResourceMatcher.ANY,
          "*",
          null);

  private static PolicyUpserts upserts(
      final List<PolicyRole> roles,
      final List<PolicyMembership> memberships,
      final List<PolicyAuthorization> authorizations) {
    return new PolicyUpserts(null, roles, null, null, memberships, authorizations);
  }

  private static PolicyDeletions deletions(
      final List<String> roleIds,
      final List<PolicyMembership> memberships,
      final List<PolicyAuthorizationKey> authorizations) {
    return new PolicyDeletions(null, roleIds, null, null, memberships, authorizations);
  }

  @Test
  void shouldNormaliseNullSectionsToEmpty() {
    final var changeSet = new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, null, null);

    assertThat(changeSet.upserts().tenants()).isEmpty();
    assertThat(changeSet.upserts().authorizations()).isEmpty();
    assertThat(changeSet.deletions().roleIds()).isEmpty();
    assertThat(changeSet.deletions().memberships()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(longs = {-1, 0})
  void shouldRejectVersionBelowOne(final long version) {
    assertThatThrownBy(() -> new PolicyChangeSet(version, PolicyChangeSetKind.DELTA, null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("policyVersion");
  }

  @Test
  void shouldRejectNullKind() {
    assertThatThrownBy(() -> new PolicyChangeSet(1, null, null, null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void shouldAcceptSnapshotWithEmptyDeletions() {
    assertThatCode(
            () ->
                new PolicyChangeSet(
                    1, PolicyChangeSetKind.SNAPSHOT, null, deletions(null, null, null)))
        .doesNotThrowAnyException();
  }

  @Test
  void shouldRejectSnapshotWithDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1, PolicyChangeSetKind.SNAPSHOT, null, deletions(List.of("r1"), null, null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("SNAPSHOT");
  }

  private static Arguments idCase(
      final String name,
      final Function<String, PolicyUpserts> up,
      final Function<String, PolicyDeletions> del) {
    return Arguments.of(Named.of(name, up), del, name);
  }

  static Stream<Arguments> idLists() {
    return Stream.of(
        idCase(
            "tenant",
            id ->
                new PolicyUpserts(
                    List.of(new PolicyTenant(id, "n", "d")), null, null, null, null, null),
            id -> new PolicyDeletions(List.of(id), null, null, null, null, null)),
        idCase(
            "role",
            id ->
                new PolicyUpserts(
                    null, List.of(new PolicyRole(id, "n", "d")), null, null, null, null),
            id -> new PolicyDeletions(null, List.of(id), null, null, null, null)),
        idCase(
            "group",
            id ->
                new PolicyUpserts(
                    null, null, List.of(new PolicyGroup(id, "n", "d")), null, null, null),
            id -> new PolicyDeletions(null, null, List.of(id), null, null, null)),
        idCase(
            "mapping rule",
            id ->
                new PolicyUpserts(
                    null,
                    null,
                    null,
                    List.of(new PolicyMappingRule(id, "n", "c", "v")),
                    null,
                    null),
            id -> new PolicyDeletions(null, null, null, List.of(id), null, null)));
  }

  @ParameterizedTest
  @MethodSource("idLists")
  void shouldRejectIdInUpsertsAndDeletions(
      final Function<String, PolicyUpserts> up,
      final Function<String, PolicyDeletions> del,
      final String what) {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, up.apply("x1"), del.apply("x1")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(what);
  }

  @ParameterizedTest
  @MethodSource("idLists")
  void shouldRejectDuplicateIdInUpsertsAndDeletions(
      final Function<String, PolicyUpserts> up,
      final Function<String, PolicyDeletions> del,
      final String what) {
    final var twiceUp = merge(up.apply("x1"), up.apply("x1"));
    final var twiceDel = merge(del.apply("x1"), del.apply("x1"));

    assertThatThrownBy(() -> new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, twiceUp, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate upserted " + what);
    assertThatThrownBy(() -> new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, null, twiceDel))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate deleted " + what);
  }

  private static PolicyUpserts merge(final PolicyUpserts a, final PolicyUpserts b) {
    return new PolicyUpserts(
        concat(a.tenants(), b.tenants()),
        concat(a.roles(), b.roles()),
        concat(a.groups(), b.groups()),
        concat(a.mappingRules(), b.mappingRules()),
        null,
        null);
  }

  private static PolicyDeletions merge(final PolicyDeletions a, final PolicyDeletions b) {
    return new PolicyDeletions(
        concat(a.tenantIds(), b.tenantIds()),
        concat(a.roleIds(), b.roleIds()),
        concat(a.groupIds(), b.groupIds()),
        concat(a.mappingRuleIds(), b.mappingRuleIds()),
        null,
        null);
  }

  private static <T> List<T> concat(final List<T> a, final List<T> b) {
    return Stream.concat(a.stream(), b.stream()).toList();
  }

  @Test
  void shouldRejectDuplicateMembershipInUpserts() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    upserts(null, List.of(MEMBERSHIP, MEMBERSHIP), null),
                    null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate upserted membership");
  }

  @Test
  void shouldRejectDuplicateMembershipInDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    null,
                    deletions(null, List.of(MEMBERSHIP, MEMBERSHIP), null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate deleted membership");
  }

  @Test
  void shouldRejectDuplicateAuthorizationKeyInDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1, PolicyChangeSetKind.DELTA, null, deletions(null, null, List.of(KEY, KEY))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate deleted authorization");
  }

  @Test
  void shouldRejectBlankDeletionId() {
    assertThatThrownBy(() -> new PolicyDeletions(List.of(" "), null, null, null, null, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PolicyDeletions(null, List.of(""), null, null, null, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PolicyDeletions(null, null, List.of(" "), null, null, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PolicyDeletions(null, null, null, List.of(" "), null, null))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectMembershipInUpsertsAndDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    upserts(null, List.of(MEMBERSHIP), null),
                    deletions(null, List.of(MEMBERSHIP), null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("membership");
  }

  @Test
  void shouldRejectAuthorizationKeyInUpsertsAndDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    upserts(
                        null,
                        null,
                        List.of(new PolicyAuthorization(KEY, Set.of(PermissionType.READ)))),
                    deletions(null, null, List.of(KEY))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("authorization");
  }

  @Test
  void shouldRejectDuplicateAuthorizationKeyInUpserts() {
    final var first = new PolicyAuthorization(KEY, Set.of(PermissionType.READ));
    final var second = new PolicyAuthorization(KEY, Set.of(PermissionType.CREATE));

    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    upserts(null, null, List.of(first, second)),
                    null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate upserted authorization");
  }

  @Test
  void shouldHoldImmutableCopies() {
    final var roles = new ArrayList<>(List.of(new PolicyRole("r1", "n", "d")));
    final var changeSet =
        new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, upserts(roles, null, null), null);
    roles.clear();

    assertThat(changeSet.upserts().roles()).hasSize(1);
    assertThatThrownBy(() -> changeSet.upserts().roles().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> changeSet.deletions().roleIds().add("x"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void shouldRejectEmptyPermissions() {
    assertThatThrownBy(() -> new PolicyAuthorization(KEY, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new PolicyAuthorization(KEY, Set.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void shouldRejectPermissionUnsupportedByResourceType() {
    assertThatThrownBy(() -> new PolicyAuthorization(KEY, Set.of(PermissionType.UPDATE)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("UPDATE");
  }
}
