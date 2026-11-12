/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.core.port.in.PrimarySecurityReloadPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.oidc.ClientCredentialsCheck;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers {@link PrimarySecurityReloadPort} and the {@link PrimaryChains} the primary chain beans
 * register with, so the primary chains can change at runtime like a scope (ADR-0040).
 */
@Configuration
public class PrimarySecurityReloadConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public PrimaryChains primaryChains(final CamundaSecurityLibraryProperties properties) {
    return new PrimaryChains(properties.getAuthentication());
  }

  @Bean
  @ConditionalOnMissingBean
  public PrimarySecurityReloadPort primarySecurityReloadPort(
      final ConfigurableListableBeanFactory beanFactory, final PrimaryChains primaryChains) {
    return new PrimarySecurityReloadService(
        beanFactory, primaryChains, new ScopeRetirement(beanFactory), new ClientCredentialsCheck());
  }
}
