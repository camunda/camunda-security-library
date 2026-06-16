/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Registers one {@link SecurityFilterChain} bean per {@link ScopedSecurityDescriptor} returned by
 * any {@link CamundaSecurityScopeProvider} beans contributed by the host application.
 *
 * <p>The registration is driven by a {@link BeanDefinitionRegistryPostProcessor} (BDRPP) declared
 * as a {@code static @Bean} so it executes before the enclosing {@code @Configuration} instance is
 * constructed — avoiding the "configuration class created too early" Spring warning. Because host
 * {@code @Configuration} parsing precedes BDRPP execution, provider beans are already registered in
 * the registry when this post-processor runs and can be instantiated early.
 *
 * <p>When no {@link CamundaSecurityScopeProvider} bean is present, this configuration registers
 * nothing — Hub and single-tenant OC remain byte-for-byte unchanged.
 *
 * <p>Each contributed chain is wrapped in an {@link OrderedSecurityFilterChainWrapper} that returns
 * {@link io.camunda.security.spring.security.CamundaSecurityFilterChainConstants#ORDER_WEBAPP_API}
 * from {@link org.springframework.core.Ordered#getOrder()}. The wrapper is required because {@code
 * DefaultSecurityFilterChain} is not {@link org.springframework.core.Ordered}; without an explicit
 * order a chain sorts last (behind the catch-all deny chain). Contributed chains reuse the primary
 * API order rather than a dedicated band: their base paths are disjoint from CSL's own matchers, so
 * the only requirement is that they sort before the catch-all deny chain.
 *
 * <p>Imports the infrastructure it consumes — {@link ScopedApiSecurityChainBuilderConfiguration}
 * (the {@link ScopedApiSecurityChainBuilder}) and {@link ScopedOidcInfrastructureConfiguration}
 * (the {@link ScopedJwtDecoderFactory} for OIDC scopes) — so a host that opts in by importing only
 * this class still gets a working scoped-chain collector. Both imported configurations expose their
 * beans via {@code @ConditionalOnMissingBean}, so importing them here and via the {@code
 * CamundaSecurityAutoConfiguration} umbrella is idempotent.
 */
@Configuration
@Import({
  ScopedApiSecurityChainBuilderConfiguration.class,
  ScopedOidcInfrastructureConfiguration.class,
  ScopedWebappSecurityChainBuilderConfiguration.class
})
public class ScopedApiSecurityConfiguration {

  /**
   * BDRPP that discovers {@link CamundaSecurityScopeProvider} beans and registers one {@link
   * SecurityFilterChain} bean definition per descriptor. Declared {@code static} so Spring does not
   * need to instantiate the enclosing {@code @Configuration} class before the post-processor runs.
   */
  @Bean
  public static BeanDefinitionRegistryPostProcessor scopedApiChainRegistrar() {
    return new ScopedApiChainRegistrar();
  }
}
