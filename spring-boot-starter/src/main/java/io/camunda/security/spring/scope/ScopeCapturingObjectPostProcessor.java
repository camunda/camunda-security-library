/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.ObjectPostProcessor;

/**
 * Stands in for Spring Security's shared {@link ObjectPostProcessor} so the objects built for a
 * scope belong to that scope.
 *
 * <p>The shared post-processor autowires and initializes every object a security configurer
 * creates, and keeps each {@link DisposableBean} among them — every {@code GenericFilterBean}
 * filter — until the application context closes. That is harmless for chains built once, but a
 * scope rebuilt or removed at runtime would leave all of its filters, and what they reference,
 * reachable for the life of the context.
 *
 * <p>While {@link #capturing} runs, this processor does what the shared one does — {@link
 * AutowireCapableBeanFactory#initializeBean} and {@link AutowireCapableBeanFactory#autowireBean} —
 * and hands the result to the scope's {@link ScopeObjects} instead of keeping it. Outside of it,
 * and on every thread that builds no scope, it delegates to the shared processor unchanged.
 *
 * <p>{@link ScopeObjectPostProcessorInstaller} puts it in place of the shared bean, so Spring
 * Security's own {@code HttpSecurity} prototype uses it without CSL reaching into framework state.
 */
final class ScopeCapturingObjectPostProcessor
    implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {

  private static final ThreadLocal<ScopeObjects> CAPTURE = new ThreadLocal<>();

  private final ObjectPostProcessor<Object> delegate;
  private final AutowireCapableBeanFactory beanFactory;
  private final List<ScopeObjects> builtBeforeStartup = new ArrayList<>();
  private boolean started;

  ScopeCapturingObjectPostProcessor(
      final ObjectPostProcessor<Object> delegate, final AutowireCapableBeanFactory beanFactory) {
    this.delegate = delegate;
    this.beanFactory = beanFactory;
  }

  /**
   * Runs {@code build} on this thread with every object Spring Security post-processes handed to
   * {@code objects}. Nested calls are rejected: a scope is built by one generation at a time.
   */
  static <T> T capturing(final ScopeObjects objects, final Supplier<T> build) {
    if (CAPTURE.get() != null) {
      throw new IllegalStateException("A scope build is already running on this thread");
    }
    CAPTURE.set(objects);
    try {
      return build.get();
    } finally {
      CAPTURE.remove();
    }
  }

  /**
   * Hands the generation's {@link SmartInitializingSingleton}s their callback: right away once the
   * context has started, otherwise when it does, as the shared processor would.
   */
  void initialize(final ScopeObjects objects) {
    synchronized (builtBeforeStartup) {
      if (!started) {
        builtBeforeStartup.add(objects);
        return;
      }
    }
    objects.initializeSingletons();
  }

  @Override
  @SuppressWarnings("unchecked")
  public <O> O postProcess(final O object) {
    final var objects = CAPTURE.get();
    if (objects == null || object == null) {
      return delegate.postProcess(object);
    }
    final O initialized;
    try {
      initialized = (O) beanFactory.initializeBean(object, object.toString());
    } catch (final RuntimeException ex) {
      throw new IllegalStateException(
          "Could not postProcess " + object + " of type " + object.getClass(), ex);
    }
    beanFactory.autowireBean(object);
    objects.add(initialized);
    return initialized;
  }

  @Override
  public void afterSingletonsInstantiated() {
    if (delegate instanceof final SmartInitializingSingleton singleton) {
      singleton.afterSingletonsInstantiated();
    }
    final List<ScopeObjects> pending;
    synchronized (builtBeforeStartup) {
      started = true;
      pending = List.copyOf(builtBeforeStartup);
      builtBeforeStartup.clear();
    }
    pending.forEach(ScopeObjects::initializeSingletons);
  }

  @Override
  public void destroy() throws Exception {
    if (delegate instanceof final DisposableBean disposable) {
      disposable.destroy();
    }
  }
}
