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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * The objects Spring Security post-processed while one generation of a scope's chains was built.
 * Spring Security's shared post-processor would keep each {@link DisposableBean} among them until
 * the application context closes; a scope keeps them here instead, so they become unreachable with
 * the generation and are destroyed when it is retired.
 */
final class ScopeObjects {

  private static final Logger LOG = LoggerFactory.getLogger(ScopeObjects.class);

  private final String basePath;
  private final List<DisposableBean> disposables = new ArrayList<>();
  private final List<SmartInitializingSingleton> singletons = new ArrayList<>();
  private int processed;

  ScopeObjects(final String basePath) {
    this.basePath = basePath;
  }

  synchronized void add(final Object processedObject) {
    processed++;
    if (processedObject instanceof final DisposableBean disposable) {
      disposables.add(disposable);
    }
    if (processedObject instanceof final SmartInitializingSingleton singleton) {
      singletons.add(singleton);
    }
  }

  /** How many objects were post-processed for this generation. */
  synchronized int processedCount() {
    return processed;
  }

  synchronized int disposableCount() {
    return disposables.size();
  }

  /**
   * Runs the callback Spring Security's post-processor runs once the context has instantiated its
   * singletons. A generation built later than that runs it right after the build.
   */
  void initializeSingletons() {
    final List<SmartInitializingSingleton> pending;
    synchronized (this) {
      pending = List.copyOf(singletons);
      singletons.clear();
    }
    pending.forEach(SmartInitializingSingleton::afterSingletonsInstantiated);
  }

  /** Destroys every disposable object and forgets them all. */
  void dispose() {
    final List<DisposableBean> toDestroy;
    synchronized (this) {
      toDestroy = new ArrayList<>(disposables);
      disposables.clear();
      singletons.clear();
    }
    for (final var disposable : toDestroy) {
      try {
        disposable.destroy();
      } catch (final Exception e) {
        LOG.warn(
            "Failed to destroy {} of retired scope basePath={}",
            disposable.getClass().getName(),
            basePath,
            e);
      }
    }
  }
}
