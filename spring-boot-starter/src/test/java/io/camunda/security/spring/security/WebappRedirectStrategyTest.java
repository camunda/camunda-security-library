/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.WebappRedirectStrategy.REDIRECT_MESSAGE_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.springframework.http.HttpStatus.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.Writer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class WebappRedirectStrategyTest {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private final WebappRedirectStrategy redirectStrategy = new WebappRedirectStrategy(OBJECT_MAPPER);

  @Mock private ObjectMapper mockObjectMapper;

  @Test
  void shouldSetNoContentWhenUrlIsNull() throws IOException {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();

    // when
    redirectStrategy.sendRedirect(request, response, null);

    // then
    assertThat(response.getStatus()).isEqualTo(NO_CONTENT.value());
  }

  @Test
  void shouldSetNoContentWhenUrlIsDefault() throws IOException {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();

    // when
    redirectStrategy.sendRedirect(request, response, "/");

    // then
    assertThat(response.getStatus()).isEqualTo(NO_CONTENT.value());
  }

  @Test
  void shouldSetUrlWhenUrlIsPresentAndReturnOk() throws Exception {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final String url = "/some/valid/redirect";

    // when
    redirectStrategy.sendRedirect(request, response, url);

    // then
    assertThat(response.getStatus()).isEqualTo(OK.value());
    assertThat(response.getHeader("Content-Type")).startsWith("application/json");
    assertThat(OBJECT_MAPPER.readTree(response.getContentAsString()).get("url").asText())
        .isEqualTo(url);
  }

  @Test
  void shouldReturnNoContentWithLogoutMessageHeaderWhenAttributeIsPresent() throws Exception {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();
    final String message = "The identity provider's end_session_endpoint is not available.";
    request.setAttribute(REDIRECT_MESSAGE_ATTRIBUTE, message);

    // when
    redirectStrategy.sendRedirect(request, response, "/");

    // then
    assertThat(response.getStatus()).isEqualTo(NO_CONTENT.value());
    assertThat(response.getHeader("X-Logout-Message")).isEqualTo(message);
  }

  @Test
  void shouldStripCrLfFromLogoutMessageHeader() throws IOException {
    // given
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();
    request.setAttribute(REDIRECT_MESSAGE_ATTRIBUTE, "line1\r\nX-Injected: evil");

    // when
    redirectStrategy.sendRedirect(request, response, "/");

    // then
    assertThat(response.getStatus()).isEqualTo(NO_CONTENT.value());
    assertThat(response.getHeader("X-Logout-Message")).isEqualTo("line1X-Injected: evil");
  }

  @Test
  void shouldPropagateExceptionWhenObjectMapperFails() throws Exception {
    // given
    final WebappRedirectStrategy failingStrategy = new WebappRedirectStrategy(mockObjectMapper);

    final MockHttpServletRequest request = new MockHttpServletRequest();
    final MockHttpServletResponse response = new MockHttpServletResponse();

    doThrow(new IOException("Some exception"))
        .when(mockObjectMapper)
        .writeValue(any(Writer.class), any());

    // when / then
    assertThatThrownBy(
            () -> failingStrategy.sendRedirect(request, response, "/some/valid/redirect"))
        .isInstanceOf(IOException.class);
  }
}
