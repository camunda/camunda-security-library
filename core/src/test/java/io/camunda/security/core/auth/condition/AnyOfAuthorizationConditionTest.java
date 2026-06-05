/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.auth.condition;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import io.camunda.security.api.model.authz.AuthorizationResourceType;
import io.camunda.security.api.model.authz.PermissionType;
import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.List;
import org.junit.jupiter.api.Test;

class AnyOfAuthorizationConditionTest {

  private static RequiredAuthorization<String> auth(final String resourceId) {
    return RequiredAuthorization.<String>of(
            b ->
                b.resourceType(AuthorizationResourceType.PROCESS_DEFINITION)
                    .permissionType(PermissionType.READ)
                    .resourceId(resourceId))
        .withCondition(doc -> doc.equals(resourceId));
  }

  @Test
  void shouldRejectNull() {
    assertThatIllegalArgumentException().isThrownBy(() -> new AnyOfAuthorizationCondition(null));
  }

  @Test
  void shouldRejectEmptyList() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new AnyOfAuthorizationCondition(List.of()));
  }

  @Test
  void shouldMakeDefensiveCopy() {
    final var list = new java.util.ArrayList<RequiredAuthorization<?>>();
    list.add(auth("id1"));
    final var condition = new AnyOfAuthorizationCondition(list);
    list.clear();
    assertThat(condition.authorizations()).hasSize(1);
  }

  @Test
  void shouldReturnAllAuthorizationsFromApplicableWhenConditionMatches() {
    final var a1 = auth("id1");
    final var a2 = auth("id2");
    final var condition = new AnyOfAuthorizationCondition(List.of(a1, a2));
    assertThat(condition.applicableAuthorizations("id1")).containsExactly(a1);
  }

  @Test
  void shouldReturnEmptyWhenNoConditionMatches() {
    final var a1 = auth("id1");
    final var a2 = auth("id2");
    final var condition = new AnyOfAuthorizationCondition(List.of(a1, a2));
    assertThat(condition.applicableAuthorizations("other")).isEmpty();
  }
}
