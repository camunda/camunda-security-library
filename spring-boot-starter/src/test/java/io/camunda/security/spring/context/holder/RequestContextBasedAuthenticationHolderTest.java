/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context.holder;

import static io.camunda.security.spring.context.holder.RequestContextBasedAuthenticationHolder.CAMUNDA_AUTHENTICATION_REQUEST_HOLDER_KEY;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

import io.camunda.security.api.model.CamundaAuthentication;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

@ExtendWith(MockitoExtension.class)
public class RequestContextBasedAuthenticationHolderTest {

  @Mock private RequestAttributes requestAttributes;
  @Mock private HttpServletRequest request;
  private RequestContextBasedAuthenticationHolder holder;

  @BeforeEach
  void setup() {
    RequestContextHolder.setRequestAttributes(requestAttributes);
    holder = new RequestContextBasedAuthenticationHolder(request);
  }

  @AfterEach
  void tearDown() {
    RequestContextHolder.resetRequestAttributes();
  }

  @Test
  public void shouldNotSupportWhenNoRequestAttributesBound() {
    // given
    RequestContextHolder.resetRequestAttributes();

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isFalse();
  }

  @Test
  public void shouldSupportWhenNoSessionExists() {
    // given
    when(request.getSession(eq(false))).thenReturn(null);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isTrue();
  }

  @Test
  public void shouldNotSupportWhenSessionExists() {
    // given
    final var session = mock(HttpSession.class);
    when(request.getSession(eq(false))).thenReturn(session);

    // when
    final var result = holder.supports();

    // then
    assertThat(result).isFalse();
  }

  @Test
  public void shouldReturnAuthentication() {
    // given
    final var authentication = mock(CamundaAuthentication.class);
    when(requestAttributes.getAttribute(
            eq(CAMUNDA_AUTHENTICATION_REQUEST_HOLDER_KEY), eq(SCOPE_REQUEST)))
        .thenReturn(authentication);

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(authentication);
  }

  @Test
  public void shouldAddAuthenticationToRequest() {
    // given
    final var authentication = mock(CamundaAuthentication.class);

    // when
    holder.set(authentication);

    // then
    verify(requestAttributes, times(1))
        .setAttribute(
            eq(CAMUNDA_AUTHENTICATION_REQUEST_HOLDER_KEY), eq(authentication), eq(SCOPE_REQUEST));
  }

  @Test
  public void shouldClearAuthenticationFromRequest() {
    // when
    holder.clear();

    // then
    verify(requestAttributes, times(1))
        .removeAttribute(eq(CAMUNDA_AUTHENTICATION_REQUEST_HOLDER_KEY), eq(SCOPE_REQUEST));
  }
}
