/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.context.holder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.camunda.security.api.context.CamundaAuthenticationHolder;
import io.camunda.security.api.model.CamundaAuthentication;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CamundaAuthenticationDelegatingHolderTest {

  @Test
  void shouldDelegateGetToFirstSupportingHolder() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationHolder delegate = mock();
    when(delegate.supports()).thenReturn(true);
    when(delegate.get()).thenReturn(expected);

    final var holder = new CamundaAuthenticationDelegatingHolder(List.of(delegate));

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(expected);
  }

  @Test
  void shouldDelegateSetToFirstSupportingHolder() {
    // given
    final var authentication = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationHolder delegate = mock();
    when(delegate.supports()).thenReturn(true);

    final var holder = new CamundaAuthenticationDelegatingHolder(List.of(delegate));

    // when
    holder.set(authentication);

    // then
    verify(delegate).set(authentication);
  }

  @Test
  void shouldDelegateClearToFirstSupportingHolder() {
    // given
    final CamundaAuthenticationHolder delegate = mock();
    when(delegate.supports()).thenReturn(true);

    final var holder = new CamundaAuthenticationDelegatingHolder(List.of(delegate));

    // when
    holder.clear();

    // then
    verify(delegate).clear();
  }

  @Test
  void shouldSkipNonSupportingHoldersAndDelegateToFirstSupporting() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationHolder unsupported = mock();
    when(unsupported.supports()).thenReturn(false);

    final CamundaAuthenticationHolder supported = mock();
    when(supported.supports()).thenReturn(true);
    when(supported.get()).thenReturn(expected);

    final var holder = new CamundaAuthenticationDelegatingHolder(List.of(unsupported, supported));

    // when
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(expected);
  }

  @Test
  void shouldReturnNullWhenNoHolderSupports() {
    // given
    final CamundaAuthenticationHolder unsupported = mock();
    when(unsupported.supports()).thenReturn(false);

    final var holder = new CamundaAuthenticationDelegatingHolder(List.of(unsupported));

    // when
    final var result = holder.get();

    // then
    assertThat(result).isNull();
  }

  @Test
  void shouldNotRecurseWhenSelfIsIncludedInHoldersList() {
    // given
    final var expected = CamundaAuthentication.of(b -> b.user("foo"));

    final CamundaAuthenticationHolder delegate = mock();
    when(delegate.supports()).thenReturn(true);
    when(delegate.get()).thenReturn(expected);

    // Build a holder that contains itself in the delegate list.
    // Without the self-exclusion guard this would recurse indefinitely.
    final var delegates = new ArrayList<CamundaAuthenticationHolder>();
    final var holder = new CamundaAuthenticationDelegatingHolder(delegates);
    delegates.add(holder); // self-reference — the guard must skip this
    delegates.add(delegate);

    // when — must not recurse or throw StackOverflowError
    final var result = holder.get();

    // then
    assertThat(result).isEqualTo(expected);
  }
}
