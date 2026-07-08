/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.authz.PropertyAuthorizationEvaluatorRegistry;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring configuration that wires an {@link AuthorizationService} bean when the host provides an
 * {@link AuthorizationChecker}.
 *
 * <p>This class is activated when the host explicitly imports it (directly or via the {@link
 * io.camunda.security.spring.CamundaSecurityAutoConfiguration} umbrella) and an {@link
 * AuthorizationChecker} bean is present. Hosts that need a custom {@link AuthorizationCheckPort}
 * implementation can register their own bean; the {@link ConditionalOnMissingBean} on the factory
 * method gates on the port interface so the library-supplied default backs off for any {@link
 * AuthorizationCheckPort} implementation, not only an {@link AuthorizationService} override.
 *
 * <p>All {@link PropertyAuthorizationEvaluator} beans present in the context are collected into a
 * {@link PropertyAuthorizationEvaluatorRegistry} and passed to the service constructor. Hosts
 * register their own evaluators as Spring beans to have them picked up automatically.
 *
 * <p><strong>Ordering note:</strong> same timing constraint as {@link
 * AuthorizationCheckerConfiguration} — activate via the {@link
 * io.camunda.security.spring.CamundaSecurityAutoConfiguration} umbrella so that {@link
 * ConditionalOnBean} evaluates after all host configurations have been processed.
 */
@Configuration
@ConditionalOnBean(AuthorizationChecker.class)
public class AuthorizationConfiguration {

  /**
   * Provides the default {@link AuthorizationService} backed by the host-supplied {@link
   * AuthorizationChecker} and any registered {@link PropertyAuthorizationEvaluator} beans. Backs
   * off via {@link ConditionalOnMissingBean} if the host registers its own {@link
   * AuthorizationCheckPort} bean.
   *
   * @param authorizationChecker the scope evaluation kernel
   * @param evaluators all registered property-based evaluators; empty list is valid
   * @param properties CSL configuration properties for authorization and multi-tenancy flags
   * @param claimsConverter converter from raw JWT claims to {@link
   *     io.camunda.security.api.model.CamundaAuthentication}; provided by the host application
   */
  @Bean
  @ConditionalOnMissingBean(AuthorizationCheckPort.class)
  public AuthorizationService authorizationService(
      final AuthorizationChecker authorizationChecker,
      final List<PropertyAuthorizationEvaluator<?>> evaluators,
      final CamundaSecurityLibraryProperties properties,
      final LazyTokenClaimsConverter claimsConverter) {
    return new AuthorizationService(
        authorizationChecker,
        new PropertyAuthorizationEvaluatorRegistry(evaluators),
        properties.getAuthorizations().isEnabled(),
        properties.getMultiTenancy().isChecksEnabled(),
        claimsConverter);
  }
}
