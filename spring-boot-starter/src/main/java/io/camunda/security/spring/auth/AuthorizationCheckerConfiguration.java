/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.auth;

import io.camunda.security.core.auth.AuthorizationChecker;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnBean(AuthorizationScopeRepositoryPort.class)
public class AuthorizationCheckerConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public AuthorizationChecker authorizationChecker(
      final AuthorizationScopeRepositoryPort scopeRepository) {
    return new AuthorizationChecker(scopeRepository);
  }
}
