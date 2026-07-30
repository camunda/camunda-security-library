/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class TenantAccessTest {

  @Nested
  class IsAuthorizedForTenantId {

    @Test
    void shouldReturnTrueForWildcardRegardlessOfTenant() {
      // given
      final var access = TenantAccess.wildcard(List.of());

      // when - then
      assertThat(access.isAuthorizedForTenantId("any-tenant")).isTrue();
    }

    @Test
    void shouldReturnTrueWhenAllowedTenantContainsId() {
      // given
      final var access = TenantAccess.allowed(List.of("t1", "t2"));

      // when - then
      assertThat(access.isAuthorizedForTenantId("t2")).isTrue();
    }

    @Test
    void shouldReturnFalseWhenAllowedTenantDoesNotContainId() {
      // given
      final var access = TenantAccess.allowed(List.of("t1", "t2"));

      // when - then
      assertThat(access.isAuthorizedForTenantId("t3")).isFalse();
    }

    @Test
    void shouldReturnFalseWhenDeniedEvenIfIdIsListed() {
      // given - a denied verdict carries the requested id but grants no access
      final var access = TenantAccess.denied(List.of("t1"));

      // when - then
      assertThat(access.isAuthorizedForTenantId("t1")).isFalse();
    }

    @Test
    void shouldReturnFalseWhenDeniedWithNullTenantIds() {
      // given - search backends produce denied(null) when no tenants are resolved
      final var access = TenantAccess.denied(null);

      // when - then
      assertThat(access.isAuthorizedForTenantId("t1")).isFalse();
    }

    @Test
    void shouldReturnFalseWhenAllowedWithEmptyTenantList() {
      // given
      final var access = TenantAccess.allowed(List.of());

      // when - then
      assertThat(access.isAuthorizedForTenantId("t1")).isFalse();
    }
  }

  @Nested
  class IsAuthorizedForTenantIds {

    @Test
    void shouldReturnTrueForWildcardRegardlessOfTenants() {
      // given
      final var access = TenantAccess.wildcard(List.of());

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of("a", "b"))).isTrue();
    }

    @Test
    void shouldReturnTrueWhenAllowedTenantsContainAllRequested() {
      // given
      final var access = TenantAccess.allowed(List.of("t1", "t2", "t3"));

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of("t1", "t3"))).isTrue();
    }

    @Test
    void shouldReturnFalseWhenAllowedTenantsMissAnyRequested() {
      // given
      final var access = TenantAccess.allowed(List.of("t1", "t2"));

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of("t2", "t3"))).isFalse();
    }

    @Test
    void shouldReturnTrueForEmptyRequestedListWhenAllowed() {
      // given - vacuously authorized for no tenants (mirrors containsAll semantics)
      final var access = TenantAccess.allowed(List.of("t1"));

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of())).isTrue();
    }

    @Test
    void shouldReturnFalseWhenRequestedTenantListIsNull() {
      // given
      final var access = TenantAccess.allowed(List.of("t1"));

      // when - then
      assertThat(access.isAuthorizedForTenantIds(null)).isFalse();
    }

    @Test
    void shouldReturnFalseWhenDenied() {
      // given
      final var access = TenantAccess.denied(List.of("t1"));

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of("t1"))).isFalse();
    }

    @Test
    void shouldReturnFalseWhenDeniedWithNullTenantIds() {
      // given
      final var access = TenantAccess.denied(null);

      // when - then
      assertThat(access.isAuthorizedForTenantIds(List.of("t1"))).isFalse();
    }
  }
}
