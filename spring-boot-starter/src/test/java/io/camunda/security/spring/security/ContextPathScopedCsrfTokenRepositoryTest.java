/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

class ContextPathScopedCsrfTokenRepositoryTest {

  @Test
  void shouldPrependServletContextPathToCookiePath() {
    // given
    final var delegate = new CookieCsrfTokenRepository();
    final var repository = new ContextPathScopedCsrfTokenRepository(delegate, "/tenant-a");
    final var request = new MockHttpServletRequest();
    request.setContextPath("/ctx");
    final var response = new MockHttpServletResponse();

    // when
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    assertThat(response.getHeaders("Set-Cookie"))
        .as("Set-Cookie must contain an entry with Path=/ctx/tenant-a")
        .anyMatch(h -> h.contains("Path=/ctx/tenant-a"));
  }

  @Test
  void shouldPrependServletContextPathWhenLoadingDeferredToken() {
    // given
    final var delegate = new CookieCsrfTokenRepository();
    final var repository =
        new ContextPathScopedCsrfTokenRepository(delegate, "/physical-tenants/default");
    final var request = new MockHttpServletRequest();
    request.setContextPath("/core");
    final var response = new MockHttpServletResponse();

    // when
    repository.loadDeferredToken(request, response).get();

    // then
    assertThat(response.getHeaders("Set-Cookie"))
        .as("Set-Cookie must contain an entry with Path=/core/physical-tenants/default")
        .anyMatch(h -> h.contains("Path=/core/physical-tenants/default"));
  }
}
