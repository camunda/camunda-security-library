/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@ExtendWith(MockitoExtension.class)
class SecurityFilterChainSupportCustomizerTest {

  @Mock private HttpSecurity http;
  @Mock private CspCustomizer cspCustomizer;
  @Mock private SecurityHeadersCustomizer securityHeadersCustomizer;

  @Test
  void applyCspCustomizersInvokesEveryRegisteredCustomizer() throws Exception {
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
  void applySecurityHeadersCustomizersInvokesEveryRegisteredCustomizer() throws Exception {
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
