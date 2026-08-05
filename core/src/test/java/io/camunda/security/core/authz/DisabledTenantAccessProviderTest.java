/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.CamundaAuthentication;
import org.junit.jupiter.api.Test;

class DisabledTenantAccessProviderTest {

  private final DisabledTenantAccessProvider tenantAccessProvider =
      new DisabledTenantAccessProvider();

  @Test
  void shouldWildcardResolveTenantAccessRegardlessOfAuthentication() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));

    // when
    final var result = tenantAccessProvider.resolveTenantAccess(authentication);

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
    assertThat(result.tenantIds()).isNull();
  }

  @Test
  void shouldWildcardHasTenantAccessRegardlessOfResource() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));
    final var resource = new Object();

    // when
    final var result = tenantAccessProvider.hasTenantAccess(authentication, resource);

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
    assertThat(result.tenantIds()).isNull();
  }

  @Test
  void shouldWildcardHasTenantAccessByTenantIdRegardlessOfTenantId() {
    // given
    final var authentication = CamundaAuthentication.of(a -> a.user("foo"));

    // when
    final var result = tenantAccessProvider.hasTenantAccessByTenantId(authentication, "any");

    // then
    assertThat(result.denied()).isFalse();
    assertThat(result.allowed()).isTrue();
    assertThat(result.wildcard()).isTrue();
    assertThat(result.tenantIds()).isNull();
  }
}
