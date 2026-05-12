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
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CamundaAuthenticationTest {

  @Test
  void shouldFailToConvertWithUsernameAndClientId() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> CamundaAuthentication.of(b -> b.user("foo").clientId("bar")));
  }

  @Test
  void shouldFailToCreateWithUsernameAndClientId() {
    assertThatThrownBy(
            () ->
                new CamundaAuthentication(
                    "foo", "bar", false, List.of(), List.of(), List.of(), List.of(), Map.of()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Only one of username or clientId may be set");
  }

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

  @Test
  void shouldNotInvokeSupplierUntilFieldIsAccessed() {
    final var invocations = new AtomicInteger();
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .roleIdsSupplier(
                        () -> {
                          invocations.incrementAndGet();
                          return List.of("role-1");
                        }));

    assertThat(invocations).hasValue(0);

    assertThat(authentication.authenticatedRoleIds()).containsExactly("role-1");
    assertThat(invocations).hasValue(1);
  }

  @Test
  void shouldMemoizeSupplierAcrossMultipleReads() {
    final var invocations = new AtomicInteger();
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .groupIdsSupplier(
                        () -> {
                          invocations.incrementAndGet();
                          return List.of("group-1", "group-2");
                        }));

    final var first = authentication.authenticatedGroupIds();
    final var second = authentication.authenticatedGroupIds();

    assertThat(first).containsExactly("group-1", "group-2");
    assertThat(second).containsExactly("group-1", "group-2");
    assertThat(first.size()).isEqualTo(2);
    assertThat(second.iterator().next()).isEqualTo("group-1");
    assertThat(invocations).hasValue(1);
  }

  @Test
  void shouldReleaseSupplierReferenceAfterMaterialization() throws Exception {
    final var authentication =
        CamundaAuthentication.of(
            b -> b.user("demo-user").groupIdsSupplier(() -> List.of("group-1", "group-2")));

    final var groups = authentication.authenticatedGroupIds();
    assertThat(groups).isInstanceOf(LazyList.class);

    final var supplierField = LazyList.class.getDeclaredField("supplier");
    supplierField.setAccessible(true);
    assertThat(supplierField.get(groups)).isNotNull();

    assertThat(groups).containsExactly("group-1", "group-2");

    assertThat(supplierField.get(groups)).isNull();
  }

  @Test
  void shouldExposeLazySuppliersForAllFourMembershipFields() {
    final var groupCalls = new AtomicInteger();
    final var roleCalls = new AtomicInteger();
    final var tenantCalls = new AtomicInteger();
    final var mappingCalls = new AtomicInteger();

    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .groupIdsSupplier(
                        () -> {
                          groupCalls.incrementAndGet();
                          return List.of("group-1");
                        })
                    .roleIdsSupplier(
                        () -> {
                          roleCalls.incrementAndGet();
                          return List.of("role-1");
                        })
                    .tenantsSupplier(
                        () -> {
                          tenantCalls.incrementAndGet();
                          return List.of("tenant-1");
                        })
                    .mappingRulesSupplier(
                        () -> {
                          mappingCalls.incrementAndGet();
                          return List.of("rule-1");
                        }));

    assertThat(groupCalls).hasValue(0);
    assertThat(roleCalls).hasValue(0);
    assertThat(tenantCalls).hasValue(0);
    assertThat(mappingCalls).hasValue(0);

    // Accessing one field must not materialise the others.
    assertThat(authentication.authenticatedTenantIds()).containsExactly("tenant-1");

    assertThat(groupCalls).hasValue(0);
    assertThat(roleCalls).hasValue(0);
    assertThat(tenantCalls).hasValue(1);
    assertThat(mappingCalls).hasValue(0);
  }

  @Test
  void shouldNormalizeNullSupplierResultToEmptyList() {
    final var authentication =
        CamundaAuthentication.of(b -> b.user("demo-user").groupIdsSupplier(() -> null));

    assertThat(authentication.authenticatedGroupIds()).isEmpty();
  }

  @Test
  void shouldRejectBothEagerValuesAndSupplierForSameField() {
    assertThatExceptionOfType(IllegalStateException.class)
        .isThrownBy(
            () ->
                CamundaAuthentication.of(
                    b ->
                        b.user("demo-user")
                            .role("role-1")
                            .roleIdsSupplier(() -> List.of("role-2"))))
        .withMessageContaining("roleIds");
  }

  @Test
  void shouldThrowOnMutationOfLazyList() {
    final var authentication =
        CamundaAuthentication.of(
            b -> b.user("demo-user").groupIdsSupplier(() -> List.of("group-1")));

    assertThatThrownBy(() -> authentication.authenticatedGroupIds().add("group-2"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void shouldPreserveLazinessThroughCanonicalConstructor() {
    final var invocations = new AtomicInteger();
    final var lazy =
        CamundaAuthentication.of(
                b ->
                    b.user("demo-user")
                        .groupIdsSupplier(
                            () -> {
                              invocations.incrementAndGet();
                              return List.of("group-1");
                            }))
            .authenticatedGroupIds();

    // Round-trip the list through the canonical constructor and verify the supplier still hasn't
    // run — the constructor's defensive-copy step must not eagerly materialise a LazyList.
    final var rebuilt =
        new CamundaAuthentication("demo-user", null, false, lazy, null, null, null, null);

    assertThat(invocations).hasValue(0);
    assertThat(rebuilt.authenticatedGroupIds()).containsExactly("group-1");
    assertThat(invocations).hasValue(1);
  }

  @Test
  void shouldEqualEagerAuthenticationWithSameMaterializedContent() {
    final var eager =
        CamundaAuthentication.of(
            b -> b.user("demo-user").group("group-1").role("role-1").tenant("tenant-1"));
    final var lazy =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .groupIdsSupplier(() -> List.of("group-1"))
                    .roleIdsSupplier(() -> List.of("role-1"))
                    .tenantsSupplier(() -> List.of("tenant-1")));

    assertThat(lazy).isEqualTo(eager);
    assertThat(lazy.hashCode()).isEqualTo(eager.hashCode());
  }

  @Test
  void shouldSerializeLazyAuthenticationAsMaterializedLists() throws Exception {
    final var authentication =
        CamundaAuthentication.of(
            b ->
                b.user("demo-user")
                    .groupIdsSupplier(() -> List.of("group-1", "group-2"))
                    .roleIdsSupplier(() -> List.of("role-1")));

    final var bytes = new ByteArrayOutputStream();
    try (var out = new ObjectOutputStream(bytes)) {
      out.writeObject(authentication);
    }

    final CamundaAuthentication restored;
    try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      restored = (CamundaAuthentication) in.readObject();
    }

    assertThat(restored.authenticatedUsername()).isEqualTo("demo-user");
    assertThat(restored.authenticatedGroupIds()).containsExactly("group-1", "group-2");
    assertThat(restored.authenticatedRoleIds()).containsExactly("role-1");
    assertThat(restored.authenticatedTenantIds()).isEmpty();
    assertThat(restored.authenticatedMappingRuleIds()).isEmpty();
  }
}
