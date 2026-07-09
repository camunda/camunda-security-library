/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationRejectionTest {

  @Test
  void tenantRejectionHoldsTenantId() {
    final var r = new AuthorizationRejection.Tenant("t1");
    assertThat(r.tenantId()).isEqualTo("t1");
  }

  @Test
  void tenantIsInstanceOfAuthorizationRejection() {
    assertThat(new AuthorizationRejection.Tenant("t1")).isInstanceOf(AuthorizationRejection.class);
  }

  @Test
  void permissionRejectionHoldsAllFields() {
    final var r =
        new AuthorizationRejection.Permission(
            AuthorizationResourceType.PROCESS_DEFINITION, PermissionType.READ, "proc-1");
    assertThat(r.resourceType()).isEqualTo(AuthorizationResourceType.PROCESS_DEFINITION);
    assertThat(r.permissionType()).isEqualTo(PermissionType.READ);
    assertThat(r.resourceId()).isEqualTo("proc-1");
  }

  @Test
  void permissionIsInstanceOfAuthorizationRejection() {
    assertThat(
            new AuthorizationRejection.Permission(
                AuthorizationResourceType.PROCESS_DEFINITION, PermissionType.READ, "x"))
        .isInstanceOf(AuthorizationRejection.class);
  }

  @Test
  void tenantAndPermissionAreDistinctSubtypes() {
    final AuthorizationRejection tenant = new AuthorizationRejection.Tenant("t");
    final AuthorizationRejection permission =
        new AuthorizationRejection.Permission(
            AuthorizationResourceType.PROCESS_DEFINITION, PermissionType.READ, "r");
    assertThat(tenant).isNotInstanceOf(AuthorizationRejection.Permission.class);
    assertThat(permission).isNotInstanceOf(AuthorizationRejection.Tenant.class);
  }

  @Test
  void propertyRejectionHoldsAllFields() {
    final var r =
        new AuthorizationRejection.Property(
            AuthorizationResourceType.USER_TASK, PermissionType.READ, Set.of("assignee"));
    assertThat(r.resourceType()).isEqualTo(AuthorizationResourceType.USER_TASK);
    assertThat(r.permissionType()).isEqualTo(PermissionType.READ);
    assertThat(r.propertyNames()).containsExactly("assignee");
  }

  @Test
  void propertyIsInstanceOfAuthorizationRejection() {
    assertThat(
            new AuthorizationRejection.Property(
                AuthorizationResourceType.USER_TASK, PermissionType.READ, Set.of("assignee")))
        .isInstanceOf(AuthorizationRejection.class);
  }

  @Test
  void propertyRejectionRejectsNullPropertyNames() {
    assertThatThrownBy(
            () ->
                new AuthorizationRejection.Property(
                    AuthorizationResourceType.USER_TASK, PermissionType.READ, null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("propertyNames");
  }

  @Test
  void propertyRejectionSortsPropertyNames() {
    final var r =
        new AuthorizationRejection.Property(
            AuthorizationResourceType.USER_TASK,
            PermissionType.READ,
            new HashSet<>(Set.of("candidateUsers", "assignee")));
    assertThat(r.propertyNames()).containsExactly("assignee", "candidateUsers");
  }

  @Test
  void propertyRejectionDefensivelyCopiesPropertyNames() {
    final var mutableInput = new HashSet<>(Set.of("assignee"));
    final var r =
        new AuthorizationRejection.Property(
            AuthorizationResourceType.USER_TASK, PermissionType.READ, mutableInput);
    mutableInput.add("candidateUsers");
    assertThat(r.propertyNames()).containsExactly("assignee");
  }

  @Test
  void propertyRejectionExposesUnmodifiablePropertyNames() {
    final var r =
        new AuthorizationRejection.Property(
            AuthorizationResourceType.USER_TASK, PermissionType.READ, Set.of("assignee"));
    assertThatThrownBy(() -> r.propertyNames().add("candidateUsers"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void switchOnSubtypeIsExhaustive() {
    // Compile-time exhaustiveness check — adding a new subtype breaks this.
    final AuthorizationRejection r = new AuthorizationRejection.Tenant("t");
    final String label =
        switch (r) {
          case AuthorizationRejection.Tenant t -> "tenant:" + t.tenantId();
          case AuthorizationRejection.Permission p -> "permission:" + p.resourceId();
          case AuthorizationRejection.Property p -> "property:" + p.propertyNames();
        };
    assertThat(label).isEqualTo("tenant:t");
  }
}
