/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.ScopeChainViewTest.generation;
import static io.camunda.security.spring.scope.ScopeChainViewTest.request;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletResponse;

class ScopeDispatchingSecurityFilterChainTest {

  private static final String BASE = "/tenants/t1";

  private final ScopeSlots slots = new ScopeSlots();
  private final ScopeDispatchingSecurityFilterChain dispatcher =
      new ScopeDispatchingSecurityFilterChain(slots, 1);

  @Test
  void shouldRunTheApiChainOfTheMatchedGeneration() {
    // given
    final var first = generation(1);
    slots.slotFor(BASE).publish(first);

    // when
    final var matched = dispatcher.matches(request(BASE + "/v2/x"));
    slots.slotFor(BASE).publish(generation(2));

    // then
    assertThat(matched).isTrue();
    assertThat(dispatcher.getFilters()).isSameAs(first.api().getFilters());
  }

  @Test
  void shouldRunTheWebappChainForAWebappPath() {
    // given
    final var first = generation(1);
    slots.slotFor(BASE).publish(first);

    // when
    final var matched = dispatcher.matches(request(BASE + "/app/home"));

    // then
    assertThat(matched).isTrue();
    assertThat(dispatcher.getFilters()).isSameAs(first.webapp().getFilters());
  }

  @Test
  void shouldNotMatchAPathNeitherChainOfTheScopeClaims() {
    // given
    slots.slotFor(BASE).publish(generation(1));

    // when / then
    assertThat(dispatcher.matches(request(BASE + "/static/logo.png"))).isFalse();
    assertThat(dispatcher.matches(request("/elsewhere/v2/x"))).isFalse();
  }

  @Test
  void shouldNotMatchAScopeThatHasNoGenerationYet() {
    // given
    slots.slotFor(BASE);

    // when / then
    assertThat(dispatcher.matches(request(BASE + "/v2/x"))).isFalse();
  }

  @Test
  void shouldAnswerNotFoundForTheWholeBasePathOfARemovedScope() {
    // given
    slots.slotFor(BASE).publish(ScopeGeneration.tombstone(2, BASE));

    // when / then
    assertThat(dispatcher.matches(request(BASE + "/static/logo.png"))).isTrue();
  }

  @Test
  void shouldFailClosedWhenAskedForFiltersWithoutAMatch() throws Exception {
    // given
    final var response = new MockHttpServletResponse();
    final var next = new MockFilterChain();

    // when
    for (final var filter : dispatcher.getFilters()) {
      filter.doFilter(request(BASE + "/v2/x"), response, next);
    }

    // then
    assertThat(response.getStatus()).isEqualTo(404);
    assertThat(next.getRequest()).isNull();
  }
}
