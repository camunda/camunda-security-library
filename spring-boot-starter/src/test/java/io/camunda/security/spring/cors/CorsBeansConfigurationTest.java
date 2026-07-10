/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.cors;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Verifies the host-override contract of {@link CorsBeansConfiguration}: CSL registers a no-op
 * default when the host does not provide a {@link CorsConfigurationSource} bean, and the host bean
 * takes priority when one is present.
 */
class CorsBeansConfigurationTest {

  @Test
  void registersNoOpSourceWhenHostDoesNot() {
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(CorsBeansConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(CorsConfigurationSource.class);
              assertThat(ctx.getBean(CorsConfigurationSource.class))
                  .as(
                      "default must be the NoOpCorsConfigurationSource marker so the filter chain disables CORS")
                  .isInstanceOf(NoOpCorsConfigurationSource.class);
            });
  }

  @Test
  void hostProvidedBeanTakesPriority() {
    final CorsConfigurationSource hostSource = request -> null;
    new ApplicationContextRunner()
        .withBean(CorsConfigurationSource.class, () -> hostSource)
        .withConfiguration(AutoConfigurations.of(CorsBeansConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(CorsConfigurationSource.class);
              assertThat(ctx.getBean(CorsConfigurationSource.class))
                  .as("host-provided CorsConfigurationSource must override the CSL default")
                  .isSameAs(hostSource);
            });
  }
}
