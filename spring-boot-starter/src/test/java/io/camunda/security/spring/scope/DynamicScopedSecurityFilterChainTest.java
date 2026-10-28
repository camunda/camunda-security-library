/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

class DynamicScopedSecurityFilterChainTest {

  private static DefaultSecurityFilterChain scope(
      final String basePath, final String name, final List<String> trace) {
    return new DefaultSecurityFilterChain(
        PathPatternRequestMatcher.withDefaults().matcher(basePath + "/**"),
        (request, response, chain) -> {
          trace.add(name);
          chain.doFilter(request, response);
        });
  }

  @Test
  void reportsItsOrder() {
    assertThat(new DynamicScopedSecurityFilterChain(42).getOrder()).isEqualTo(42);
  }

  @Test
  void matchesNothingUntilScopesArePublished() {
    final var chain = new DynamicScopedSecurityFilterChain(0);

    assertThat(chain.matches(new MockHttpServletRequest("GET", "/a/x"))).isFalse();
  }

  @Test
  void runsOnlyTheFiltersOfTheMatchingScopeThenContinues() throws Exception {
    final var trace = new ArrayList<String>();
    final var chain = new DynamicScopedSecurityFilterChain(0);
    chain.replace(Map.of("/a", scope("/a", "a", trace), "/b", scope("/b", "b", trace)));
    final var request = new MockHttpServletRequest("GET", "/b/x");
    final var next = new MockFilterChain();

    assertThat(chain.matches(request)).isTrue();
    chain.getFilters().getFirst().doFilter(request, new MockHttpServletResponse(), next);

    assertThat(trace).containsExactly("b");
    assertThat(next.getRequest()).as("the request continues past the scope's filters").isNotNull();
  }

  @Test
  void failsClosedWhenTheScopeIsRemovedBetweenMatchAndDispatch() throws Exception {
    final var chain = new DynamicScopedSecurityFilterChain(0);
    chain.replace(Map.of("/a", scope("/a", "a", new ArrayList<>())));
    final var request = new MockHttpServletRequest("GET", "/a/x");
    assertThat(chain.matches(request)).isTrue();
    chain.replace(Map.of());
    final var response = new MockHttpServletResponse();
    final var next = new MockFilterChain();

    chain.getFilters().getFirst().doFilter(request, response, next);

    assertThat(response.getStatus()).isEqualTo(404);
    assertThat(next.getRequest()).isNull();
  }

  @Test
  void replaceDoesNotKeepAReferenceToTheCallersMap() {
    final var chain = new DynamicScopedSecurityFilterChain(0);
    final var scopes =
        new java.util.HashMap<String, org.springframework.security.web.SecurityFilterChain>();
    chain.replace(scopes);

    scopes.put("/a", scope("/a", "a", new ArrayList<>()));

    assertThat(chain.chains()).isEmpty();
  }
}
