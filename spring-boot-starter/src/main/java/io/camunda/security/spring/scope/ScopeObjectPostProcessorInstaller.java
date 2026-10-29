/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.core.PriorityOrdered;
import org.springframework.security.config.ObjectPostProcessor;

/**
 * Replaces Spring Security's shared {@code objectPostProcessor} bean with a {@link
 * ScopeCapturingObjectPostProcessor} that delegates to it, so the objects of a scope's chains are
 * owned by the scope.
 *
 * <p>Ordered first so the shared bean is wrapped even when another post-processor depends on it.
 */
final class ScopeObjectPostProcessorInstaller
    implements BeanPostProcessor, BeanFactoryAware, PriorityOrdered {

  /** The name {@code ObjectPostProcessorConfiguration} gives the shared processor. */
  static final String SHARED_PROCESSOR_BEAN_NAME = "objectPostProcessor";

  private AutowireCapableBeanFactory beanFactory;

  @Override
  public void setBeanFactory(final BeanFactory beanFactory) throws BeansException {
    if (beanFactory instanceof final AutowireCapableBeanFactory autowiring) {
      this.beanFactory = autowiring;
    }
  }

  @Override
  @SuppressWarnings("unchecked")
  public Object postProcessAfterInitialization(final Object bean, final String beanName) {
    if (beanFactory != null
        && SHARED_PROCESSOR_BEAN_NAME.equals(beanName)
        && bean instanceof ObjectPostProcessor<?>
        && !(bean instanceof ScopeCapturingObjectPostProcessor)) {
      return new ScopeCapturingObjectPostProcessor((ObjectPostProcessor<Object>) bean, beanFactory);
    }
    return bean;
  }

  @Override
  public int getOrder() {
    return HIGHEST_PRECEDENCE;
  }
}
