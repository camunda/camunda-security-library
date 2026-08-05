/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TenantAccessProviderTest {

  @Test
  void shouldReturnDefaultProviderWhenMultiTenancyChecksEnabled() {
    assertThat(TenantAccessProvider.of(true)).isInstanceOf(DefaultTenantAccessProvider.class);
  }

  @Test
  void shouldReturnDisabledProviderWhenMultiTenancyChecksDisabled() {
    assertThat(TenantAccessProvider.of(false)).isInstanceOf(DisabledTenantAccessProvider.class);
  }
}
