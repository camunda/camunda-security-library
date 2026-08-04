/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class SessionHeartbeatFilterTest {

  private final SessionHeartbeatFilter filter = new SessionHeartbeatFilter();

  @Test
  void respondsNoContentForPostToHeartbeatPathAndDoesNotContinueTheChain() throws Exception {
    final var request = new MockHttpServletRequest("POST", "/operate/session/heartbeat");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NO_CONTENT);
    assertThat(chain.getRequest())
        .as("must not continue the chain — a heartbeat call needs no further processing")
        .isNull();
  }

  @Test
  void matchesTheHeartbeatPathOnAnyScope() throws Exception {
    final var request =
        new MockHttpServletRequest("POST", "/physical-tenants/t1/session/heartbeat");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_NO_CONTENT);
    assertThat(chain.getRequest()).isNull();
  }

  @Test
  void passesThroughRequestsToOtherPaths() throws Exception {
    final var request = new MockHttpServletRequest("GET", "/operate/v2/tasks");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest())
        .as("an ordinary request must continue down the chain unmodified")
        .isNotNull();
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
  }

  @Test
  void doesNotMatchGetToTheHeartbeatPath() throws Exception {
    // The endpoint is POST-only; a GET to the same path is not recognized so it falls through
    // (and would 404 or whatever else the rest of the chain does with it — not this filter's
    // concern).
    final var request = new MockHttpServletRequest("GET", "/operate/session/heartbeat");
    final var response = new MockHttpServletResponse();
    final var chain = new MockFilterChain();

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
  }
}
