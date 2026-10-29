/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.security.config.ObjectPostProcessor;

class ScopeObjectPostProcessorInstallerTest {

  private final ObjectPostProcessor<Object> shared =
      new ObjectPostProcessor<>() {
        @Override
        public <O> O postProcess(final O object) {
          return object;
        }
      };

  @Test
  void shouldWrapSpringSecuritysSharedProcessor() {
    // given
    final var installer = installer();

    // when
    final var bean =
        installer.postProcessAfterInitialization(
            shared, ScopeObjectPostProcessorInstaller.SHARED_PROCESSOR_BEAN_NAME);

    // then
    assertThat(bean).isInstanceOf(ScopeCapturingObjectPostProcessor.class);
  }

  @Test
  void shouldLeaveOtherProcessorsAlone() {
    // when
    final var bean = installer().postProcessAfterInitialization(shared, "anotherProcessor");

    // then
    assertThat(bean).isSameAs(shared);
  }

  @Test
  void shouldNotWrapTwice() {
    // given
    final var installer = installer();
    final var wrapped =
        installer.postProcessAfterInitialization(
            shared, ScopeObjectPostProcessorInstaller.SHARED_PROCESSOR_BEAN_NAME);

    // when
    final var again =
        installer.postProcessAfterInitialization(
            wrapped, ScopeObjectPostProcessorInstaller.SHARED_PROCESSOR_BEAN_NAME);

    // then
    assertThat(again).isSameAs(wrapped);
  }

  private static ScopeObjectPostProcessorInstaller installer() {
    final var installer = new ScopeObjectPostProcessorInstaller();
    installer.setBeanFactory(new DefaultListableBeanFactory());
    return installer;
  }
}
