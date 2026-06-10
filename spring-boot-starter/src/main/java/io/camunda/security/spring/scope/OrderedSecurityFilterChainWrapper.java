/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Objects;
import org.springframework.core.Ordered;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Delegates all {@link SecurityFilterChain} methods to a wrapped chain while implementing {@link
 * Ordered} with a fixed order value. This is necessary because {@link
 * org.springframework.security.web.DefaultSecurityFilterChain} does not implement {@link Ordered},
 * and bean-definition order attributes do not affect {@link
 * org.springframework.security.web.FilterChainProxy} ordering.
 */
final class OrderedSecurityFilterChainWrapper implements SecurityFilterChain, Ordered {

  private final SecurityFilterChain delegate;
  private final int order;

  OrderedSecurityFilterChainWrapper(final SecurityFilterChain delegate, final int order) {
    this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    this.order = order;
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    return delegate.matches(request);
  }

  @Override
  public List<Filter> getFilters() {
    return delegate.getFilters();
  }

  @Override
  public int getOrder() {
    return order;
  }
}
