/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

@ExtendWith(MockitoExtension.class)
class ApiTokenRefreshSupportTest {

  @Mock private OAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private OAuth2AuthorizedClientManager authorizedClientManager;

  @Test
  void primaryChainLogoutClearsTheUnscopedSessionAndCsrfCookies() {
    final var support =
        ApiTokenRefreshSupport.forPrimaryChain(authorizedClientRepository, authorizedClientManager);

    final var response = logout(support, "");

    assertThat(response.getCookie("camunda-session")).isNotNull();
    assertThat(response.getCookie("camunda-session").getMaxAge()).isZero();
    assertThat(response.getCookie("X-CSRF-TOKEN")).isNotNull();
    assertThat(response.getCookie("X-CSRF-TOKEN").getMaxAge()).isZero();
  }

  @Test
  void scopedLogoutClearsTheScopeCookiesOnTheScopePath() {
    final var support =
        ApiTokenRefreshSupport.forScope(
            authorizedClientRepository,
            authorizedClientManager,
            "/physical-tenants/a",
            "camunda-session-physical-tenants-a",
            "X-CSRF-TOKEN-physical-tenants-a");

    final var response = logout(support, "");

    final var session = response.getCookie("camunda-session-physical-tenants-a");
    assertThat(session).isNotNull();
    assertThat(session.getMaxAge()).isZero();
    assertThat(session.getPath()).isEqualTo("/physical-tenants/a");
    final var csrf = response.getCookie("X-CSRF-TOKEN-physical-tenants-a");
    assertThat(csrf).isNotNull();
    assertThat(csrf.getPath()).isEqualTo("/physical-tenants/a");
  }

  @Test
  void scopedLogoutPrependsTheServletContextPath() {
    final var support =
        ApiTokenRefreshSupport.forScope(
            authorizedClientRepository,
            authorizedClientManager,
            "/physical-tenants/a",
            "camunda-session-physical-tenants-a",
            "X-CSRF-TOKEN-physical-tenants-a");

    final var response = logout(support, "/operate");

    assertThat(response.getCookie("camunda-session-physical-tenants-a").getPath())
        .as("the clear path must match the path the cookie was set on under any deployment")
        .isEqualTo("/operate/physical-tenants/a");
  }

  @Test
  void rejectsMissingCollaborators() {
    assertThatNullPointerException()
        .isThrownBy(
            () -> new ApiTokenRefreshSupport(null, authorizedClientManager, (r, s, a) -> {}));
    assertThatNullPointerException()
        .isThrownBy(
            () -> new ApiTokenRefreshSupport(authorizedClientRepository, null, (r, s, a) -> {}));
    assertThatNullPointerException()
        .isThrownBy(
            () ->
                new ApiTokenRefreshSupport(
                    authorizedClientRepository, authorizedClientManager, null));
  }

  private static MockHttpServletResponse logout(
      final ApiTokenRefreshSupport support, final String contextPath) {
    final var request = new MockHttpServletRequest("GET", contextPath + "/api/anything");
    request.setContextPath(contextPath);
    final var response = new MockHttpServletResponse();
    support
        .logoutHandler()
        .logout(
            request,
            response,
            new UsernamePasswordAuthenticationToken("alice", null, java.util.List.of()));
    return response;
  }
}
