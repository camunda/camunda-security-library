/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.CamundaAuthentication;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class ClaimsBasedTenantAccessProviderTest {

  private final ClaimsBasedTenantAccessProvider provider = new ClaimsBasedTenantAccessProvider();

  @Nested
  class ResolveTenantAccess {

    @Test
    void shouldAllowTheAuthenticatedTenants() {
      // given
      final var authentication = CamundaAuthentication.of(b -> b.tenants(List.of("t1", "t2")));

      // when
      final var access = provider.resolveTenantAccess(authentication);

      // then
      assertThat(access.allowed()).isTrue();
      assertThat(access.wildcard()).isFalse();
      assertThat(access.tenantIds()).containsExactly("t1", "t2");
    }

    @Test
    void shouldDenyWhenNoTenantsAreAuthenticated() {
      // given
      final var authentication = CamundaAuthentication.none();

      // when
      final var access = provider.resolveTenantAccess(authentication);

      // then
      assertThat(access.denied()).isTrue();
    }
  }

  @Nested
  class HasTenantAccessByTenantId {

    @Test
    void shouldAllowWhenTenantIsAuthenticated() {
      // given
      final var authentication = CamundaAuthentication.of(b -> b.tenants(List.of("t1", "t2")));

      // when
      final var access = provider.hasTenantAccessByTenantId(authentication, "t2");

      // then
      assertThat(access.allowed()).isTrue();
      assertThat(access.tenantIds()).containsExactly("t2");
    }

    @Test
    void shouldDenyWhenTenantIsNotAuthenticated() {
      // given
      final var authentication = CamundaAuthentication.of(b -> b.tenants(List.of("t1")));

      // when
      final var access = provider.hasTenantAccessByTenantId(authentication, "t3");

      // then
      assertThat(access.denied()).isTrue();
      assertThat(access.tenantIds()).containsExactly("t3");
    }

    @Test
    void shouldDenyWhenNoTenantsAreAuthenticated() {
      // given
      final var authentication = CamundaAuthentication.none();

      // when
      final var access = provider.hasTenantAccessByTenantId(authentication, "t1");

      // then
      assertThat(access.denied()).isTrue();
    }
  }

  @Nested
  class HasTenantAccess {

    @Test
    void shouldRejectPerResourceResolution() {
      // given
      final var authentication = CamundaAuthentication.of(b -> b.tenants(List.of("t1")));

      // when - then: core cannot extract a tenant from an arbitrary resource, so it fails loudly
      // rather than fail-open
      assertThatThrownBy(() -> provider.hasTenantAccess(authentication, new Object()))
          .isInstanceOf(UnsupportedOperationException.class);
    }
  }
}
