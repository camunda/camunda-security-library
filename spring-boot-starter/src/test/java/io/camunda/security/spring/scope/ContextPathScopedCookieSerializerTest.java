/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

class ContextPathScopedCookieSerializerTest {

  @Test
  void shouldPrependServletContextPathToCookiePath() {
    // given
    final var delegate = new DefaultCookieSerializer();
    final var serializer = new ContextPathScopedCookieSerializer(delegate, "/tenant-a");
    final var request = new MockHttpServletRequest();
    request.setContextPath("/ctx");
    final var response = new MockHttpServletResponse();

    // when
    serializer.writeCookieValue(new CookieSerializer.CookieValue(request, response, "session-id"));

    // then
    assertThat(response.getHeaders("Set-Cookie"))
        .as("Set-Cookie must contain an entry with Path=/ctx/tenant-a")
        .anyMatch(h -> h.contains("Path=/ctx/tenant-a"));
  }
}
