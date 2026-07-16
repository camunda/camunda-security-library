/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class SecurityFilterChainSupportCustomizerTest {

  @Test
  void applyCspCustomizersInvokesEveryRegisteredCustomizer() throws Exception {
    final HttpSecurity http = mock(HttpSecurity.class);
    final CspCustomizer customizer = mock(CspCustomizer.class);
    final ObjectProvider<CspCustomizer> provider =
        objectProviderOf(CspCustomizer.class, customizer);

    SecurityFilterChainSupport.applyCspCustomizers(http, provider);

    verify(customizer, times(1)).customize(http);
  }

  @Test
  void applyCspCustomizersIsNoOpWhenNoneRegistered() throws Exception {
    final HttpSecurity http = mock(HttpSecurity.class);
    final ObjectProvider<CspCustomizer> provider = emptyObjectProvider();

    SecurityFilterChainSupport.applyCspCustomizers(http, provider);

    verifyNoInteractions(http);
  }

  @Test
  void applySecurityHeadersCustomizersInvokesEveryRegisteredCustomizer() throws Exception {
    final HttpSecurity http = mock(HttpSecurity.class);
    final SecurityHeadersCustomizer customizer = mock(SecurityHeadersCustomizer.class);
    final ObjectProvider<SecurityHeadersCustomizer> provider =
        objectProviderOf(SecurityHeadersCustomizer.class, customizer);

    SecurityFilterChainSupport.applySecurityHeadersCustomizers(http, provider);

    verify(customizer, times(1)).customize(http);
  }

  @Test
  void applySecurityHeadersCustomizersIsNoOpWhenNoneRegistered() throws Exception {
    final HttpSecurity http = mock(HttpSecurity.class);
    final ObjectProvider<SecurityHeadersCustomizer> provider = emptyObjectProvider();

    SecurityFilterChainSupport.applySecurityHeadersCustomizers(http, provider);

    verifyNoInteractions(http);
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
}
