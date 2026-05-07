/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.context.CamundaAuthenticationHolder;
import io.camunda.security.api.model.CamundaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
public class DefaultCamundaAuthenticationProviderTest {

  @Mock private CamundaAuthenticationHolder holder;
  @Mock private CamundaAuthenticationConverter<Authentication> authenticationConverter;
  @Mock private Authentication springAuthentication;
  @InjectMocks private DefaultCamundaAuthenticationProvider authenticationProvider;

  @AfterEach
  void tearDown() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void shouldReturnAuthenticationFromHolder() {
    // given
    final var expectedAuthentication = CamundaAuthentication.of(b -> b.user("foo"));

    SecurityContextHolder.getContext().setAuthentication(springAuthentication);
    when(holder.get()).thenReturn(expectedAuthentication);

    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isNotNull();
    assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
  }

  @Test
  void shouldConvertAndHoldAuthentication() {
    // given
    final var expectedAuthentication = CamundaAuthentication.of(b -> b.user("foo"));

    SecurityContextHolder.getContext().setAuthentication(springAuthentication);
    when(authenticationConverter.convert(eq(springAuthentication)))
        .thenReturn(expectedAuthentication);

    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isNotNull();
    assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
    verify(holder).set(eq(expectedAuthentication));
  }

  @Test
  void shouldConvertWhenHolderReturnsNull() {
    // given
    final var expectedAuthentication = CamundaAuthentication.of(b -> b.user("foo"));

    SecurityContextHolder.getContext().setAuthentication(springAuthentication);
    when(holder.get()).thenReturn(null);
    when(authenticationConverter.convert(eq(springAuthentication)))
        .thenReturn(expectedAuthentication);

    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
    verify(holder).get();
    verify(authenticationConverter).convert(eq(springAuthentication));
    verify(holder).set(eq(expectedAuthentication));
  }

  @Test
  void shouldConvertButNotCacheIfAnonymous() {
    // given
    final var expectedAuthentication = CamundaAuthentication.anonymous();

    SecurityContextHolder.getContext().setAuthentication(springAuthentication);
    when(authenticationConverter.convert(eq(springAuthentication)))
        .thenReturn(expectedAuthentication);

    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isNotNull();
    assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
    verify(holder, times(0)).set(eq(expectedAuthentication));
  }

  @Test
  void shouldAllowNeitherUsernameOrClientWhenAnonymous() {
    // given
    final var expectedAuthentication = CamundaAuthentication.anonymous();

    SecurityContextHolder.getContext().setAuthentication(springAuthentication);
    when(holder.get()).thenReturn(expectedAuthentication);

    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isNotNull();
    assertThat(actualAuthentication).isEqualTo(expectedAuthentication);
  }

  @Test
  void shouldClearHolderWhenSpringAuthenticationIsMissing() {
    // when
    final var actualAuthentication = authenticationProvider.getCamundaAuthentication();

    // then
    assertThat(actualAuthentication).isNull();
    verify(holder).clear();
    verifyNoInteractions(authenticationConverter);
  }
}
