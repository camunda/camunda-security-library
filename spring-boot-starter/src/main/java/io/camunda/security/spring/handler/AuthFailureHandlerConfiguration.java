/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provides the default {@link AuthFailureHandler} bean. Hosts can override it by registering their
 * own {@link AuthFailureHandler} bean — the {@code @ConditionalOnMissingBean} ensures the library's
 * default backs off.
 */
@Configuration
public class AuthFailureHandlerConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AuthFailureHandler authFailureHandler(final ObjectMapper objectMapper) {
    return new JsonProblemDetailAuthFailureHandler(objectMapper);
  }
}
