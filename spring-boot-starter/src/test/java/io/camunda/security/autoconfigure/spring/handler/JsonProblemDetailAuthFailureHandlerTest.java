/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.handler;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

class JsonProblemDetailAuthFailureHandlerTest {

  private JsonProblemDetailAuthFailureHandler handler;
  private MockHttpServletRequest request;
  private MockHttpServletResponse response;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @BeforeEach
  void setUp() {
    handler = new JsonProblemDetailAuthFailureHandler(objectMapper);
    request = new MockHttpServletRequest();
    request.setRequestURI("/api/test");
    response = new MockHttpServletResponse();
  }

  @Test
  void shouldReturnUnauthorizedOnAuthenticationFailure() throws Exception {
    handler.onAuthenticationFailure(
        request, response, new BadCredentialsException("bad credentials"));

    assertThat(response.getStatus()).isEqualTo(401);
    assertThat(response.getContentType()).startsWith(MediaType.APPLICATION_PROBLEM_JSON_VALUE);

    final var body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("type").asText()).isEqualTo("about:blank");
    assertThat(body.get("title").asText()).isEqualTo("Unauthorized");
    assertThat(body.get("status").asInt()).isEqualTo(401);
    assertThat(body.get("detail").asText()).isEqualTo("bad credentials");
    assertThat(body.get("instance").asText()).isEqualTo("/api/test");
  }

  @Test
  void shouldReturnUnauthorizedOnCommence() throws Exception {
    handler.commence(request, response, new BadCredentialsException("invalid token"));

    assertThat(response.getStatus()).isEqualTo(401);

    final var body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("status").asInt()).isEqualTo(401);
    assertThat(body.get("detail").asText()).isEqualTo("invalid token");
  }

  @Test
  void shouldReturnUnauthorizedWhenNotAuthenticated() throws Exception {
    handler.handle(request, response, new AccessDeniedException("access denied"));

    assertThat(response.getStatus()).isEqualTo(401);

    final var body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("title").asText()).isEqualTo("Unauthorized");
  }

  @Test
  void shouldReturnForbiddenWhenAuthenticated() throws Exception {
    final var auth =
        UsernamePasswordAuthenticationToken.authenticated("alice", null, java.util.List.of());
    request.setUserPrincipal(auth);

    handler.handle(request, response, new AccessDeniedException("access denied"));

    assertThat(response.getStatus()).isEqualTo(403);

    final var body = objectMapper.readTree(response.getContentAsString());
    assertThat(body.get("title").asText()).isEqualTo("Forbidden");
    assertThat(body.get("status").asInt()).isEqualTo(403);
  }
}
