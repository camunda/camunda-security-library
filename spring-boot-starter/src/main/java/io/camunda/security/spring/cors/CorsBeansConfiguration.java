/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.cors;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Provides a default no-op {@link CorsConfigurationSource} bean when the host has not registered
 * one. The no-op default is a {@link NoOpCorsConfigurationSource} marker instance; {@link
 * io.camunda.security.spring.security.SecurityFilterChainSupport#applyCorsConfiguration} detects
 * this type and disables CORS — preserving the previous always-disabled behaviour.
 *
 * <p>Hosts that need CORS (e.g., SPA frontends calling the API from a different origin) register
 * their own {@link CorsConfigurationSource} bean, which takes precedence via
 * {@code @ConditionalOnMissingBean}. Any host-provided source — including a {@link
 * org.springframework.web.cors.UrlBasedCorsConfigurationSource} that starts empty — is always
 * honoured and never silently disabled.
 */
@Configuration
public class CorsBeansConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public CorsConfigurationSource corsConfigurationSource() {
    return new NoOpCorsConfigurationSource();
  }
}
