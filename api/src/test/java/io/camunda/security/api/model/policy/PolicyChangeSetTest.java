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
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

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

  @Test
  void shouldNormaliseNullPermissionsToEmpty() {
    assertThat(new PolicyAuthorization(KEY, null).permissions()).isEmpty();
  }

  @Test
  void shouldRejectNegativeVersion() {
    assertThatThrownBy(() -> new PolicyChangeSet(-1, PolicyChangeSetKind.DELTA, null, null))
        .isInstanceOf(IllegalArgumentException.class);
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

  @Test
  void shouldRejectIdInUpsertsAndDeletions() {
    assertThatThrownBy(
            () ->
                new PolicyChangeSet(
                    1,
                    PolicyChangeSetKind.DELTA,
                    upserts(List.of(new PolicyRole("r1", "n", "d")), null, null),
                    deletions(List.of("r1"), null, null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("role");
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
        .hasMessageContaining("Duplicate");
  }

  @Test
  void shouldHoldImmutableCopies() {
    final var roles = new java.util.ArrayList<>(List.of(new PolicyRole("r1", "n", "d")));
    final var changeSet =
        new PolicyChangeSet(1, PolicyChangeSetKind.DELTA, upserts(roles, null, null), null);
    roles.clear();

    assertThat(changeSet.upserts().roles()).hasSize(1);
    assertThatThrownBy(() -> changeSet.upserts().roles().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> changeSet.deletions().roleIds().add("x"))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
