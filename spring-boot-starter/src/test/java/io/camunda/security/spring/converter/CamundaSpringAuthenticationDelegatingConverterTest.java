/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.exception.CamundaAuthenticationException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
public class CamundaSpringAuthenticationDelegatingConverterTest {

  @Mock private Authentication authentication;
  @Mock private CamundaAuthenticationConverter<Authentication> unsupported;
  @Mock private CamundaAuthenticationConverter<Authentication> supported;

  @Test
  void shouldDelegateToFirstSupportingConverter() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    when(supported.supports(authentication)).thenReturn(true);
    when(supported.convert(authentication)).thenReturn(expected);

    final var converter = new CamundaSpringAuthenticationDelegatingConverter(List.of(supported));

    // when
    final var result = converter.convert(authentication);

    // then
    assertThat(result).isEqualTo(expected);
  }

  @Test
  void shouldSkipNonSupportingConvertersAndDelegateToFirstSupporting() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    when(unsupported.supports(authentication)).thenReturn(false);
    when(supported.supports(authentication)).thenReturn(true);
    when(supported.convert(authentication)).thenReturn(expected);

    final var converter =
        new CamundaSpringAuthenticationDelegatingConverter(List.of(unsupported, supported));

    // when
    final var result = converter.convert(authentication);

    // then
    assertThat(result).isEqualTo(expected);
  }

  @Test
  void shouldThrowWhenNoConverterSupports() {
    // given
    when(unsupported.supports(authentication)).thenReturn(false);

    final var converter = new CamundaSpringAuthenticationDelegatingConverter(List.of(unsupported));

    // when / then
    assertThatThrownBy(() -> converter.convert(authentication))
        .isInstanceOf(CamundaAuthenticationException.class);
  }

  @Test
  void shouldReturnNullWhenAuthenticationIsNullAndNoConverterSupportsNull() {
    // given — e.g. a permit-all webapp path with no UnprotectedCamundaAuthenticationConverter
    // active: nothing declares support for a null Spring Authentication.
    when(unsupported.supports(null)).thenReturn(false);

    final var converter = new CamundaSpringAuthenticationDelegatingConverter(List.of(unsupported));

    // when
    final var result = converter.convert(null);

    // then
    assertThat(result).isNull();
  }

  @Test
  void shouldNotRecurseWhenSelfIsIncludedInConvertersList() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    when(supported.supports(authentication)).thenReturn(true);
    when(supported.convert(authentication)).thenReturn(expected);

    // Build a converter that contains itself in the delegate list.
    // Without the self-exclusion guard this would recurse infinitely.
    final var delegates = new ArrayList<CamundaAuthenticationConverter<Authentication>>();
    final var converter = new CamundaSpringAuthenticationDelegatingConverter(delegates);
    delegates.add(converter); // self-reference — the guard must skip this
    delegates.add(supported);

    // when — must not recurse or throw StackOverflowError
    final var result = converter.convert(authentication);

    // then
    assertThat(result).isEqualTo(expected);
  }
}
