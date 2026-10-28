/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import jakarta.servlet.Filter;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Releases the filters of chains that were replaced or dropped at runtime.
 *
 * <p>Spring Security's shared {@link ObjectPostProcessor} keeps every {@link DisposableBean} it
 * post-processes — which includes every {@code GenericFilterBean} filter of every chain built from
 * an {@code HttpSecurity} — in a private list that it only drains when the application context
 * closes. That is harmless for chains built once at startup, but rebuilding or dropping scopes at
 * runtime would make the list, and everything the filters reference, grow with every reload.
 *
 * <p>There is no API to remove entries, so this reaches into the processor's two lists by name. If
 * a Spring Security upgrade renames them the release is skipped with a warning, and {@code
 * ScopedSecurityChainReloadTest} fails — it asserts the lists do not grow across reloads.
 */
final class RetiredFilterReleaser {

  private static final Logger LOG = LoggerFactory.getLogger(RetiredFilterReleaser.class);

  private static final ResolvableType PROCESSOR_TYPE =
      ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, Object.class);

  private final ConfigurableListableBeanFactory beanFactory;

  RetiredFilterReleaser(final ConfigurableListableBeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  /** Destroys the filters of the given chains and forgets them in Spring Security. */
  void release(final Collection<? extends SecurityFilterChain> retired) {
    final Set<Filter> filters = Collections.newSetFromMap(new IdentityHashMap<>());
    retired.forEach(chain -> filters.addAll(chain.getFilters()));
    if (filters.isEmpty()) {
      return;
    }
    final var processor = beanFactory.getBeanProvider(PROCESSOR_TYPE).getIfUnique();
    if (processor == null) {
      return;
    }
    try {
      drain(processor, "disposableBeans", filters, true);
      drain(processor, "smartSingletons", filters, false);
    } catch (final ReflectiveOperationException | RuntimeException e) {
      LOG.warn(
          "Cannot release the filters of {} retired scoped chain(s) from {}; they stay referenced"
              + " until the application context closes",
          retired.size(),
          processor.getClass().getName(),
          e);
    }
  }

  private static void drain(
      final Object processor,
      final String fieldName,
      final Set<Filter> filters,
      final boolean destroy)
      throws ReflectiveOperationException {
    final var field = processor.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    final var retained = (List<?>) field.get(processor);
    retained.removeIf(
        object -> {
          if (!filters.contains(object)) {
            return false;
          }
          if (destroy && object instanceof DisposableBean disposable) {
            destroyQuietly(disposable);
          }
          return true;
        });
  }

  private static void destroyQuietly(final DisposableBean disposable) {
    try {
      disposable.destroy();
    } catch (final Exception e) {
      LOG.warn("Failed to destroy retired filter {}", disposable.getClass().getName(), e);
    }
  }
}
