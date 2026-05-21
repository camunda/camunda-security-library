/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.context.CamundaAuthenticationHolder;
import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder;
import io.camunda.security.spring.context.holder.RequestContextBasedAuthenticationHolder;
import io.camunda.security.spring.converter.UnprotectedCamundaAuthenticationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class CamundaAuthenticationBeansConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class,
                  CamundaAuthenticationBeansConfiguration.class));

  // ---- default bean registration -------------------------------------------

  @Test
  void requestContextBasedHolderIsRegisteredByDefault() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .getBean(
                    "requestContextBasedAuthenticationHolder", CamundaAuthenticationHolder.class)
                .isInstanceOf(RequestContextBasedAuthenticationHolder.class));
  }

  @Test
  void httpSessionBasedHolderIsRegisteredByDefault() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .getBean("httpSessionBasedAuthenticationHolder", CamundaAuthenticationHolder.class)
                .isInstanceOf(HttpSessionBasedAuthenticationHolder.class));
  }

  @Test
  void authenticationProviderIsRegisteredByDefault() {
    runner.run(
        ctx ->
            assertThat(ctx)
                .hasSingleBean(CamundaAuthenticationProvider.class)
                .getBean(CamundaAuthenticationProvider.class)
                .isInstanceOf(DefaultCamundaAuthenticationProvider.class));
  }

  @Test
  void unprotectedConverterIsRegisteredWhenApiIsUnprotected() {
    runner
        .withPropertyValues("camunda.security.authentication.unprotected-api=true")
        .run(
            ctx ->
                assertThat(ctx)
                    .getBeans(CamundaAuthenticationConverter.class)
                    .containsValue(ctx.getBean(UnprotectedCamundaAuthenticationConverter.class)));
  }

  @Test
  void unprotectedConverterIsAbsentWhenApiIsProtected() {
    runner
        .withPropertyValues("camunda.security.authentication.unprotected-api=false")
        .run(
            ctx ->
                assertThat(ctx).doesNotHaveBean(UnprotectedCamundaAuthenticationConverter.class));
  }

  // ---- @ConditionalOnMissingBean back-off ----------------------------------

  @Test
  void requestContextHolderBacksOffWhenHostProvidesOne() {
    runner
        .withUserConfiguration(HostRequestContextHolder.class)
        .run(
            ctx -> {
              assertThat(ctx)
                  .getBean(
                      "requestContextBasedAuthenticationHolder", CamundaAuthenticationHolder.class)
                  .isInstanceOf(HostRequestContextHolder.StubHolder.class);
            });
  }

  @Test
  void httpSessionHolderBacksOffWhenHostProvidesOne() {
    runner
        .withUserConfiguration(HostHttpSessionHolder.class)
        .run(
            ctx -> {
              assertThat(ctx)
                  .getBean(
                      "httpSessionBasedAuthenticationHolder", CamundaAuthenticationHolder.class)
                  .isInstanceOf(HostHttpSessionHolder.StubHolder.class);
            });
  }

  @Test
  void authenticationProviderBacksOffWhenHostProvidesOne() {
    runner
        .withUserConfiguration(HostAuthenticationProvider.class)
        .run(
            ctx -> {
              assertThat(ctx)
                  .hasSingleBean(CamundaAuthenticationProvider.class)
                  .getBean(CamundaAuthenticationProvider.class)
                  .isInstanceOf(HostAuthenticationProvider.StubProvider.class);
            });
  }

  // ---- stub host configurations --------------------------------------------

  @Configuration
  static class HostRequestContextHolder {

    @Bean
    CamundaAuthenticationHolder requestContextBasedAuthenticationHolder() {
      return new StubHolder();
    }

    static final class StubHolder implements CamundaAuthenticationHolder {
      @Override
      public boolean supports() {
        return true;
      }

      @Override
      public io.camunda.security.api.model.CamundaAuthentication get() {
        return null;
      }

      @Override
      public void set(final io.camunda.security.api.model.CamundaAuthentication authentication) {}

      @Override
      public void clear() {}
    }
  }

  @Configuration
  static class HostHttpSessionHolder {

    @Bean
    CamundaAuthenticationHolder httpSessionBasedAuthenticationHolder() {
      return new StubHolder();
    }

    static final class StubHolder implements CamundaAuthenticationHolder {
      @Override
      public boolean supports() {
        return true;
      }

      @Override
      public io.camunda.security.api.model.CamundaAuthentication get() {
        return null;
      }

      @Override
      public void set(final io.camunda.security.api.model.CamundaAuthentication authentication) {}

      @Override
      public void clear() {}
    }
  }

  @Configuration
  static class HostAuthenticationProvider {

    @Bean
    CamundaAuthenticationProvider camundaAuthenticationProvider() {
      return new StubProvider();
    }

    static final class StubProvider implements CamundaAuthenticationProvider {
      @Override
      public io.camunda.security.api.model.CamundaAuthentication getCamundaAuthentication() {
        return null;
      }
    }
  }
}
