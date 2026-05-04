/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.junit.jupiter.api.Test;

class CamundaAuthenticationTest {

  @Test
  void shouldNormalizeNullCollectionsToImmutableEmptyCollections() {
    final var authentication =
        new CamundaAuthentication("demo-user", null, false, null, null, null, null, null);

    assertThat(authentication.authenticatedGroupIds()).isEmpty();
    assertThat(authentication.authenticatedRoleIds()).isEmpty();
    assertThat(authentication.authenticatedTenantIds()).isEmpty();
    assertThat(authentication.authenticatedMappingRuleIds()).isEmpty();
    assertThat(authentication.claims()).isEmpty();

    assertThatThrownBy(() -> authentication.authenticatedGroupIds().add("group-1"))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> authentication.claims().put("sub", "demo-user"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void shouldDefensivelyCopyConstructorCollectionsAndClaims() {
    final var groupIds = new ArrayList<>(List.of("group-1"));
    final var roleIds = new ArrayList<>(List.of("role-1"));
    final var tenantIds = new ArrayList<>(List.of("tenant-1"));
    final var mappingRuleIds = new ArrayList<>(List.of("rule-1"));
    final var claims = new HashMap<String, Object>();
    claims.put("sub", "demo-user");

    final var authentication =
        new CamundaAuthentication(
            "demo-user", null, false, groupIds, roleIds, tenantIds, mappingRuleIds, claims);

    groupIds.add("group-2");
    roleIds.add("role-2");
    tenantIds.add("tenant-2");
    mappingRuleIds.add("rule-2");
    claims.put("scope", "read");

    assertThat(authentication.authenticatedGroupIds()).containsExactly("group-1");
    assertThat(authentication.authenticatedRoleIds()).containsExactly("role-1");
    assertThat(authentication.authenticatedTenantIds()).containsExactly("tenant-1");
    assertThat(authentication.authenticatedMappingRuleIds()).containsExactly("rule-1");
    assertThat(authentication.claims()).hasSize(1).containsEntry("sub", "demo-user");
  }

  @Test
  void shouldDefensivelyCopyBuilderInputs() {
    final var groupIds = new ArrayList<>(List.of("group-1"));
    final var claims = new HashMap<String, Object>();
    claims.put("sub", "demo-user");

    final var authentication =
        CamundaAuthentication.of(b -> b.user("demo-user").groupIds(groupIds).claims(claims));

    groupIds.add("group-2");
    claims.put("scope", "read");

    assertThat(authentication.authenticatedGroupIds()).containsExactly("group-1");
    assertThat(authentication.claims()).hasSize(1).containsEntry("sub", "demo-user");
  }

  @Test
  void shouldNotMutatePreviouslyBuiltAuthenticationWhenBuilderIsReused() {
    final var builder = new CamundaAuthentication.Builder().user("demo-user").group("group-1");

    final var first = builder.build();
    builder.group("group-2");
    final var second = builder.build();

    assertThat(first.authenticatedGroupIds()).containsExactly("group-1");
    assertThat(second.authenticatedGroupIds()).containsExactly("group-1", "group-2");
  }
}
