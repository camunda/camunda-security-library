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

/**
 * Direct coverage for {@link CamundaSecurityFilterChainConstants#isHeartbeatRequest}, the single
 * matching rule {@code WebSessionRepository} and {@code SessionHeartbeatFilter} both delegate to —
 * extracted so the two callers can't silently drift on what counts as a heartbeat request.
 */
class CamundaSecurityFilterChainConstantsTest {

  @Test
  void matchesPostToTheHeartbeatPath() {
    final var request = new MockHttpServletRequest("POST", "/session/heartbeat");
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)).isTrue();
  }

  @Test
  void matchesPostToAScopedHeartbeatPath() {
    final var request =
        new MockHttpServletRequest("POST", "/physical-tenants/t1/session/heartbeat");
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)).isTrue();
  }

  @Test
  void matchIsCaseInsensitiveOnMethod() {
    final var request = new MockHttpServletRequest("post", "/session/heartbeat");
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)).isTrue();
  }

  @Test
  void doesNotMatchGetToTheSamePath() {
    final var request = new MockHttpServletRequest("GET", "/session/heartbeat");
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)).isFalse();
  }

  @Test
  void doesNotMatchPostToAnUnrelatedPath() {
    final var request = new MockHttpServletRequest("POST", "/operate/v2/tasks");
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(request)).isFalse();
  }

  @Test
  void doesNotMatchANullRequest() {
    assertThat(CamundaSecurityFilterChainConstants.isHeartbeatRequest(null)).isFalse();
  }
}
