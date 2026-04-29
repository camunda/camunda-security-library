/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Default {@link AuthFailureHandler} that returns RFC 7807 Problem Details JSON responses. Hosts
 * needing a different problem-detail schema can provide their own {@link AuthFailureHandler} bean —
 * the library configurations pick the host's implementation up by type.
 */
public final class JsonProblemDetailAuthFailureHandler implements AuthFailureHandler {

  private final ObjectMapper objectMapper;

  public JsonProblemDetailAuthFailureHandler(final ObjectMapper objectMapper) {
    this.objectMapper = objectMapper;
  }

  @Override
  public void onAuthenticationFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException error)
      throws IOException {
    handleFailure(request, response, HttpStatus.UNAUTHORIZED, error);
  }

  @Override
  public void handle(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AccessDeniedException error)
      throws IOException {
    // If a token was passed but failed validation, onAuthenticationFailure handles it. When no
    // token was passed at all access is denied here — distinguish 401 vs 403 by inspecting the
    // session principal.
    final var principal = request.getUserPrincipal();
    if (principal instanceof final Authentication auth && auth.isAuthenticated()) {
      handleFailure(request, response, HttpStatus.FORBIDDEN, error);
      return;
    }

    handleFailure(request, response, HttpStatus.UNAUTHORIZED, error);
  }

  @Override
  public void commence(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException error)
      throws IOException {
    handleFailure(request, response, HttpStatus.UNAUTHORIZED, error);
  }

  private void handleFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final HttpStatus status,
      final Exception error)
      throws IOException {
    final ProblemDetail problem =
        new ProblemDetail(
            "about:blank",
            status.getReasonPhrase(),
            status.value(),
            error.getMessage(),
            request.getRequestURI());

    final String problemJson = objectMapper.writeValueAsString(problem);

    response.reset();
    response.setStatus(status.value());
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.getWriter().append(problemJson);
  }

  /** RFC 7807 Problem Details representation. */
  record ProblemDetail(String type, String title, int status, String detail, String instance) {}
}
