/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@ExtendWith(MockitoExtension.class)
class SecurityFilterChainSupportCustomizerTest {

  @Mock private HttpSecurity http;
  @Mock private CspCustomizer cspCustomizer;
  @Mock private SecurityHeadersCustomizer securityHeadersCustomizer;

  @Test
  void applyCspCustomizersInvokesRegisteredCustomizer() throws Exception {
    final ObjectProvider<CspCustomizer> provider =
        objectProviderOf(CspCustomizer.class, cspCustomizer);

    SecurityFilterChainSupport.applyCspCustomizers(http, provider);

    verify(cspCustomizer, times(1)).customize(http);
  }

  @Test
  void applyCspCustomizersIsNoOpWhenNoneRegistered() throws Exception {
    final ObjectProvider<CspCustomizer> provider = emptyObjectProvider();

    SecurityFilterChainSupport.applyCspCustomizers(http, provider);

    verifyNoInteractions(http);
  }

  @Test
  @SuppressWarnings("unchecked")
  void applyCspCustomizersInvokesMultipleRegisteredCustomizersInOrder() throws Exception {
    try (var ctx = new AnnotationConfigApplicationContext(OrderedCspCustomizersConfig.class)) {
      final ObjectProvider<CspCustomizer> provider = ctx.getBeanProvider(CspCustomizer.class);

      SecurityFilterChainSupport.applyCspCustomizers(http, provider);

      final List<String> invocationOrder =
          (List<String>) ctx.getBean("invocationOrder", List.class);
      assertThat(invocationOrder)
          .as("both registered customizers must run, in @Order sequence")
          .containsExactly("first", "second");
    }
  }

  @Test
  void applySecurityHeadersCustomizersInvokesRegisteredCustomizer() throws Exception {
    final ObjectProvider<SecurityHeadersCustomizer> provider =
        objectProviderOf(SecurityHeadersCustomizer.class, securityHeadersCustomizer);

    SecurityFilterChainSupport.applySecurityHeadersCustomizers(http, provider);

    verify(securityHeadersCustomizer, times(1)).customize(http);
  }

  @Test
  void applySecurityHeadersCustomizersIsNoOpWhenNoneRegistered() throws Exception {
    final ObjectProvider<SecurityHeadersCustomizer> provider = emptyObjectProvider();

    SecurityFilterChainSupport.applySecurityHeadersCustomizers(http, provider);

    verifyNoInteractions(http);
  }

  @Test
  @SuppressWarnings("unchecked")
  void applySecurityHeadersCustomizersInvokesMultipleRegisteredCustomizersInOrder()
      throws Exception {
    try (var ctx =
        new AnnotationConfigApplicationContext(OrderedSecurityHeadersCustomizersConfig.class)) {
      final ObjectProvider<SecurityHeadersCustomizer> provider =
          ctx.getBeanProvider(SecurityHeadersCustomizer.class);

      SecurityFilterChainSupport.applySecurityHeadersCustomizers(http, provider);

      final List<String> invocationOrder =
          (List<String>) ctx.getBean("invocationOrder", List.class);
      assertThat(invocationOrder)
          .as("both registered customizers must run, in @Order sequence")
          .containsExactly("first", "second");
    }
  }

  private static <T> ObjectProvider<T> objectProviderOf(final Class<T> type, final T bean) {
    final var factory = new StaticListableBeanFactory();
    factory.addBean("bean", bean);
    return factory.getBeanProvider(type);
  }

  private static <T> ObjectProvider<T> emptyObjectProvider() {
    return new ObjectProvider<>() {
      @Override
      public T getObject() {
        throw new IllegalStateException("no bean");
      }

      @Override
      public Stream<T> orderedStream() {
        return Stream.empty();
      }
    };
  }

  @Configuration
  static class OrderedCspCustomizersConfig {

    @Bean
    List<String> invocationOrder() {
      return new ArrayList<>();
    }

    @Bean
    @Order(1)
    CspCustomizer firstCspCustomizer(final List<String> invocationOrder) {
      return http -> invocationOrder.add("first");
    }

    @Bean
    @Order(2)
    CspCustomizer secondCspCustomizer(final List<String> invocationOrder) {
      return http -> invocationOrder.add("second");
    }
  }

  @Configuration
  static class OrderedSecurityHeadersCustomizersConfig {

    @Bean
    List<String> invocationOrder() {
      return new ArrayList<>();
    }

    @Bean
    @Order(1)
    SecurityHeadersCustomizer firstSecurityHeadersCustomizer(final List<String> invocationOrder) {
      return http -> invocationOrder.add("first");
    }

    @Bean
    @Order(2)
    SecurityHeadersCustomizer secondSecurityHeadersCustomizer(final List<String> invocationOrder) {
      return http -> invocationOrder.add("second");
    }
  }
}
