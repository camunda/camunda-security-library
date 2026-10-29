/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class ScopeSlotsTest {

  private final ScopeSlots slots = new ScopeSlots();

  @Test
  void shouldFindTheRuntimeSlotOfTheLongestBasePathPrefix() {
    // given
    final var outer = slots.slotFor("/tenants");
    final var inner = slots.slotFor("/tenants/t1");

    // when / then
    assertThat(slots.runtimeSlotFor(request("/tenants/t1/v2/x"))).isSameAs(inner);
    assertThat(slots.runtimeSlotFor(request("/tenants/t2/v2/x"))).isSameAs(outer);
    assertThat(slots.runtimeSlotFor(request("/tenants/t1"))).isSameAs(inner);
  }

  @Test
  void shouldNotMatchASegmentThatOnlyStartsLikeABasePath() {
    // given
    slots.slotFor("/tenants/t1");

    // when / then
    assertThat(slots.runtimeSlotFor(request("/tenants/t10/v2/x"))).isNull();
    assertThat(slots.runtimeSlotFor(request("/other"))).isNull();
  }

  @Test
  void shouldLeaveAStartupSlotToItsOwnChains() {
    // given
    slots.registerStartupSlot("/tenants/t1");

    // when / then
    assertThat(slots.runtimeSlotFor(request("/tenants/t1/v2/x"))).isNull();
    assertThat(slots.runtimeScopeCount()).isZero();
  }

  @Test
  void shouldIgnoreTheServletContextPath() {
    // given
    final var slot = slots.slotFor("/tenants/t1");
    final var request = request("/ctx/tenants/t1/v2/x");
    request.setContextPath("/ctx");

    // when / then
    assertThat(slots.runtimeSlotFor(request)).isSameAs(slot);
  }

  @Test
  void shouldReuseTheSlotOfABasePath() {
    // when / then
    assertThat(slots.slotFor("/tenants/t1")).isSameAs(slots.slotFor("/tenants/t1"));
    assertThat(slots.all()).hasSize(1);
  }

  @Test
  void shouldRejectASecondStartupSlotForABasePath() {
    // given
    slots.registerStartupSlot("/tenants/t1");

    // when / then
    assertThatThrownBy(() -> slots.registerStartupSlot("/tenants/t1"))
        .isInstanceOf(IllegalStateException.class);
  }

  private static MockHttpServletRequest request(final String uri) {
    return new MockHttpServletRequest("GET", uri);
  }
}
