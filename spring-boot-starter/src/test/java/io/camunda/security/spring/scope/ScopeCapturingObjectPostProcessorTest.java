/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.security.config.ObjectPostProcessor;

@ExtendWith(MockitoExtension.class)
class ScopeCapturingObjectPostProcessorTest {

  @Mock private ObjectPostProcessor<Object> shared;

  @Test
  void shouldHandWhatAScopeBuildPostProcessesToTheScope() {
    // given
    final var processor =
        new ScopeCapturingObjectPostProcessor(shared, new DefaultListableBeanFactory());
    final var objects = new ScopeObjects("/s");
    final var filter = new Disposable();

    // when
    final var processed =
        ScopeCapturingObjectPostProcessor.capturing(objects, () -> processor.postProcess(filter));

    // then
    assertThat(processed).isSameAs(filter);
    assertThat(objects.disposableCount()).isOne();
    verifyNoInteractions(shared);
  }

  @Test
  void shouldDelegateOutsideOfAScopeBuild() {
    // given
    final var processor =
        new ScopeCapturingObjectPostProcessor(shared, new DefaultListableBeanFactory());
    final var object = new Object();
    when(shared.postProcess(object)).thenReturn(object);

    // when
    processor.postProcess(object);

    // then
    verify(shared).postProcess(object);
  }

  @Test
  void shouldRejectANestedScopeBuild() {
    // given
    final var objects = new ScopeObjects("/s");

    // when / then
    assertThatThrownBy(
            () ->
                ScopeCapturingObjectPostProcessor.capturing(
                    objects,
                    () -> ScopeCapturingObjectPostProcessor.capturing(objects, () -> null)))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void shouldInitializeABuildMadeBeforeStartupOnceTheContextHasStarted() {
    // given
    final var processor =
        new ScopeCapturingObjectPostProcessor(shared, new DefaultListableBeanFactory());
    final var objects = new ScopeObjects("/s");
    final var singleton = new Singleton();
    ScopeCapturingObjectPostProcessor.capturing(objects, () -> processor.postProcess(singleton));

    // when
    processor.initialize(objects);
    final var beforeStartup = singleton.calls.get();
    processor.afterSingletonsInstantiated();

    // then
    assertThat(beforeStartup).isZero();
    assertThat(singleton.calls).hasValue(1);
  }

  @Test
  void shouldInitializeABuildMadeAfterStartupRightAway() {
    // given
    final var processor =
        new ScopeCapturingObjectPostProcessor(shared, new DefaultListableBeanFactory());
    processor.afterSingletonsInstantiated();
    final var objects = new ScopeObjects("/s");
    final var singleton = new Singleton();
    ScopeCapturingObjectPostProcessor.capturing(objects, () -> processor.postProcess(singleton));

    // when
    processor.initialize(objects);

    // then
    assertThat(singleton.calls).hasValue(1);
  }

  @Test
  void shouldDestroyWhatTheScopeOwnsWhenItIsDisposed() {
    // given
    final var objects = new ScopeObjects("/s");
    final var disposable = new Disposable();
    objects.add(disposable);

    // when
    objects.dispose();

    // then
    assertThat(disposable.destroyed).isTrue();
    assertThat(objects.disposableCount()).isZero();
  }

  static final class Disposable implements DisposableBean {
    private boolean destroyed;

    @Override
    public void destroy() {
      destroyed = true;
    }
  }

  static final class Singleton implements SmartInitializingSingleton {
    private final AtomicInteger calls = new AtomicInteger();

    @Override
    public void afterSingletonsInstantiated() {
      calls.incrementAndGet();
    }
  }
}
