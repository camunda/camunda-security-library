/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import jakarta.servlet.Filter;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

class ScopeChainViewTest {

  private static final String BASE = "/tenants/t1";

  private final ScopeSlot slot = new ScopeSlot(BASE, true);

  @Test
  void shouldRunTheFiltersOfTheGenerationThatMatched() {
    // given
    final var first = generation(1);
    final var second = generation(2);
    slot.publish(first);
    final var view = new ScopeChainView(slot, ScopeChainKind.API);

    // when
    final var matched = view.matches(request(BASE + "/v2/x"));
    slot.publish(second);

    // then
    assertThat(matched).isTrue();
    assertThat(view.getFilters()).isSameAs(first.api().getFilters());
    assertThat(view.getFilters()).isSameAs(second.api().getFilters());
  }

  @Test
  void shouldPresentTheCurrentGenerationWhenNothingMatchedFirst() {
    // given
    final var first = generation(1);
    slot.publish(first);
    final var view = new ScopeChainView(slot, ScopeChainKind.WEBAPP);
    view.matches(request(BASE + "/v2/x"));

    // when
    final var filters = view.getFilters();

    // then
    assertThat(filters).isSameAs(first.webapp().getFilters());
  }

  @Test
  void shouldAnswerForTheWholeBasePathOnceRemoved() {
    // given
    slot.publish(ScopeGeneration.tombstone(2, BASE));
    final var view = new ScopeChainView(slot, ScopeChainKind.API);

    // when / then
    assertThat(view.matches(request(BASE + "/anything"))).isTrue();
    assertThat(view.matches(request("/tenants/t2/v2/x"))).isFalse();
  }

  static ScopeGeneration generation(final long number) {
    return new ScopeGeneration(
        number,
        new ScopedSecurityDescriptor(BASE, new AuthenticationConfiguration()),
        new ScopeFingerprints("auth-" + number, "complete-" + number),
        chain(BASE + "/v2/**"),
        chain(BASE + "/app/**"),
        new ScopeObjects(BASE),
        List.of());
  }

  private static DefaultSecurityFilterChain chain(final String pattern) {
    final Filter filter = (request, response, next) -> next.doFilter(request, response);
    return new DefaultSecurityFilterChain(
        PathPatternRequestMatcher.withDefaults().matcher(pattern), filter);
  }

  static MockHttpServletRequest request(final String uri) {
    return new MockHttpServletRequest("GET", uri);
  }
}
