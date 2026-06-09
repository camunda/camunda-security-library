/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.port.out.AuthorizationScopeRepositoryPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration that wires an {@link AuthorizationChecker} bean when the host provides an
 * {@link AuthorizationScopeRepositoryPort}.
 *
 * <p>This class is activated when the host explicitly imports it (directly or via the {@link
 * io.camunda.security.spring.CamundaSecurityAutoConfiguration} umbrella) and an {@link
 * AuthorizationScopeRepositoryPort} bean is present in the application context. Hosts that need a
 * custom {@link AuthorizationChecker} can register their own bean; the {@link
 * ConditionalOnMissingBean} on the factory method ensures the library-supplied default backs off.
 */
@Configuration
@ConditionalOnBean(AuthorizationScopeRepositoryPort.class)
public class AuthorizationCheckerConfiguration {

  /**
   * Provides the default {@link AuthorizationChecker} backed by the host-supplied {@link
   * AuthorizationScopeRepositoryPort}. Back-off is handled by {@link ConditionalOnMissingBean}: if
   * the host registers its own {@link AuthorizationChecker} bean this method is skipped.
   *
   * @param scopeRepository the authorization store adapter provided by the host
   */
  @Bean
  @ConditionalOnMissingBean
  public AuthorizationChecker authorizationChecker(
      final AuthorizationScopeRepositoryPort scopeRepository) {
    return new AuthorizationChecker(scopeRepository);
  }
}
