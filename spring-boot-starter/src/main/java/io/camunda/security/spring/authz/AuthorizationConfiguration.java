/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import io.camunda.security.api.context.PropertyAuthorizationEvaluator;
import io.camunda.security.api.context.ResourceAttributeExtractor;
import io.camunda.security.core.authz.AuthorizationChecker;
import io.camunda.security.core.authz.AuthorizationService;
import io.camunda.security.core.authz.ConditionalResourceAccessProvider;
import io.camunda.security.core.authz.DisabledResourceAccessProvider;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.authz.PropertyAuthorizationEvaluatorRegistry;
import io.camunda.security.core.authz.ResourceAccessProvider;
import io.camunda.security.core.authz.ResourceAttributeExtractorRegistry;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
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
 * <p>In the same way, all {@link ResourceAttributeExtractor} beans are collected into a {@link
 * ResourceAttributeExtractorRegistry}. A resource type with an extractor evaluates the conditional
 * role memberships of the principal (ADR-0041). When at least one extractor is registered, a {@link
 * ConditionalResourceAccessProvider} resolves the list filters with the same rule, unless the host
 * registers its own {@link ResourceAccessProvider}.
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
   * <p>Wires a Micrometer-backed {@code AuthorizationCheckLatencyRecorder} when a {@link
   * MeterRegistry} bean is present; metrics are optional, so the recorder degrades to a no-op if
   * none is registered. See ADR-0019.
   *
   * @param authorizationChecker the scope evaluation kernel
   * @param evaluators all registered property-based evaluators; empty list is valid
   * @param attributeExtractors all registered resource attribute extractors; empty list is valid
   * @param properties CSL configuration properties for authorization and multi-tenancy flags
   * @param claimsConverter converter from raw JWT claims to {@link
   *     io.camunda.security.api.model.CamundaAuthentication}; provided by the host application
   * @param meterRegistry the host's {@link MeterRegistry} bean, or {@code null} if metrics are not
   *     configured
   */
  @Bean
  @ConditionalOnMissingBean(AuthorizationCheckPort.class)
  public AuthorizationService authorizationService(
      final AuthorizationChecker authorizationChecker,
      final List<PropertyAuthorizationEvaluator<?>> evaluators,
      final List<ResourceAttributeExtractor<?>> attributeExtractors,
      final CamundaSecurityLibraryProperties properties,
      final LazyTokenClaimsConverter claimsConverter,
      @Autowired(required = false) final MeterRegistry meterRegistry) {
    return new AuthorizationService(
        authorizationChecker,
        new PropertyAuthorizationEvaluatorRegistry(evaluators),
        new ResourceAttributeExtractorRegistry(attributeExtractors),
        properties.getAuthorizations().isEnabled(),
        properties.getMultiTenancy().isChecksEnabled(),
        claimsConverter,
        new MicrometerAuthorizationCheckLatencyRecorder(meterRegistry));
  }

  /**
   * Provides a {@link ConditionalResourceAccessProvider}, so that list queries count conditional
   * role memberships the same way as single checks (ADR-0041). Only created when the host registers
   * a {@link ResourceAttributeExtractor}, because without one no conditional membership counts.
   * Backs off if the host registers its own {@link ResourceAccessProvider}. A {@link
   * DisabledResourceAccessProvider} allows every resource when authorization is disabled.
   *
   * @param authorizationChecker the scope evaluation kernel
   * @param attributeExtractors all registered resource attribute extractors
   * @param properties CSL configuration properties for the authorization flag
   */
  @Bean
  @ConditionalOnBean(ResourceAttributeExtractor.class)
  @ConditionalOnMissingBean(ResourceAccessProvider.class)
  public ResourceAccessProvider conditionalResourceAccessProvider(
      final AuthorizationChecker authorizationChecker,
      final List<ResourceAttributeExtractor<?>> attributeExtractors,
      final CamundaSecurityLibraryProperties properties) {
    if (!properties.getAuthorizations().isEnabled()) {
      return new DisabledResourceAccessProvider();
    }
    return new ConditionalResourceAccessProvider(
        authorizationChecker, new ResourceAttributeExtractorRegistry(attributeExtractors));
  }
}
