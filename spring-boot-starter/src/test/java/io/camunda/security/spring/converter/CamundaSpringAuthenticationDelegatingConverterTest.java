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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.exception.CamundaAuthenticationException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

public class CamundaSpringAuthenticationDelegatingConverterTest {

  @Test
  void shouldDelegateToFirstSupportingConverter() {
    // given
    final var authentication = mock(Authentication.class);
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationConverter<Authentication> delegate = mock();
    when(delegate.supports(authentication)).thenReturn(true);
    when(delegate.convert(authentication)).thenReturn(expected);

    final var converter = new CamundaSpringAuthenticationDelegatingConverter(List.of(delegate));

    // when
    final var result = converter.convert(authentication);

    // then
    assertThat(result).isEqualTo(expected);
  }

  @Test
  void shouldSkipNonSupportingConvertersAndDelegateToFirstSupporting() {
    // given
    final var authentication = mock(Authentication.class);
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationConverter<Authentication> unsupported = mock();
    when(unsupported.supports(authentication)).thenReturn(false);

    final CamundaAuthenticationConverter<Authentication> supported = mock();
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
    final var authentication = mock(Authentication.class);

    final CamundaAuthenticationConverter<Authentication> unsupported = mock();
    when(unsupported.supports(authentication)).thenReturn(false);

    final var converter = new CamundaSpringAuthenticationDelegatingConverter(List.of(unsupported));

    // when / then
    assertThatThrownBy(() -> converter.convert(authentication))
        .isInstanceOf(CamundaAuthenticationException.class);
  }

  @Test
  void shouldNotRecurseWhenSelfIsIncludedInConvertersList() {
    // given
    final var authentication = mock(Authentication.class);
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationConverter<Authentication> delegate = mock();
    when(delegate.supports(authentication)).thenReturn(true);
    when(delegate.convert(authentication)).thenReturn(expected);

    // Build a converter that contains itself in the delegate list.
    // Without the self-exclusion guard this would recurse infinitely.
    final var delegates = new java.util.ArrayList<CamundaAuthenticationConverter<Authentication>>();
    final var converter = new CamundaSpringAuthenticationDelegatingConverter(delegates);
    delegates.add(converter); // self-reference — the guard must skip this
    delegates.add(delegate);

    // when — must not recurse or throw StackOverflowError
    final var result = converter.convert(authentication);

    // then
    assertThat(result).isEqualTo(expected);
  }
}
