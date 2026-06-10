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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Unit tests for {@link OrderedSecurityFilterChainWrapper}: it must report the fixed order it was
 * constructed with and otherwise delegate every {@link SecurityFilterChain} call to the wrapped
 * chain unchanged.
 */
@ExtendWith(MockitoExtension.class)
final class OrderedSecurityFilterChainWrapperTest {

  @Mock private SecurityFilterChain delegate;
  @Mock private HttpServletRequest request;
  @Mock private Filter filter;

  @Test
  void rejectsNullDelegate() {
    assertThatNullPointerException()
        .isThrownBy(() -> new OrderedSecurityFilterChainWrapper(null, 0))
        .withMessageContaining("delegate");
  }

  @Test
  void getOrderReturnsTheConfiguredOrder() {
    final var wrapper = new OrderedSecurityFilterChainWrapper(delegate, 4242);

    assertThat(wrapper.getOrder()).isEqualTo(4242);
  }

  @Test
  void matchesDelegatesToWrappedChain() {
    when(delegate.matches(request)).thenReturn(true);
    final var wrapper = new OrderedSecurityFilterChainWrapper(delegate, 0);

    assertThat(wrapper.matches(request)).isTrue();
    verify(delegate).matches(request);
  }

  @Test
  void getFiltersDelegatesToWrappedChain() {
    final List<Filter> filters = List.of(filter);
    when(delegate.getFilters()).thenReturn(filters);
    final var wrapper = new OrderedSecurityFilterChainWrapper(delegate, 0);

    assertThat(wrapper.getFilters()).isSameAs(filters);
    verify(delegate).getFilters();
  }
}
