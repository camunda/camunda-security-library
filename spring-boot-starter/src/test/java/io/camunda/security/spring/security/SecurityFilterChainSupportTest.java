/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Unit tests for {@link SecurityFilterChainSupport#cookieCsrfTokenRepository}. */
final class SecurityFilterChainSupportTest {

  private static CamundaSecurityLibraryProperties csrfEnabledProperties() {
    final var props = new CamundaSecurityLibraryProperties();
    props.getCsrf().setEnabled(true);
    props.getCsrf().setCookieHttpOnly(false);
    return props;
  }

  @Test
  void shouldSetCsrfCookiePathWhenCookiePathProvided() {
    // given
    final var properties = csrfEnabledProperties();
    final var cookiePath = "/physical-tenants/t1";

    // when
    final var repository =
        SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, cookiePath);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("CSRF cookie must have Path=" + cookiePath)
        .isEqualTo(cookiePath);
  }

  @Test
  void shouldNotSetCookiePathWhenNullCookiePathProvided() {
    // given
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties, null);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    // No path set — Spring uses request context path or "/" by default
    assertThat(cookie.getPath())
        .as("CSRF cookie must not have the scoped cookie path")
        .doesNotContain("/physical-tenants");
  }

  @Test
  void shouldNotSetCookiePathWhenSingleArgOverloadUsed() {
    // given
    final var properties = csrfEnabledProperties();

    // when
    final var repository = SecurityFilterChainSupport.cookieCsrfTokenRepository(properties);
    final var request = new MockHttpServletRequest();
    final var response = new MockHttpServletResponse();
    final var token = repository.generateToken(request);
    repository.saveToken(token, request, response);

    // then
    final var cookie = response.getCookie("X-CSRF-TOKEN");
    assertThat(cookie).as("CSRF cookie must be set").isNotNull();
    assertThat(cookie.getPath())
        .as("primary chain CSRF cookie must not have a scoped path")
        .doesNotContain("/physical-tenants");
  }
}
