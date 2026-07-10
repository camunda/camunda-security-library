/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.security.HttpsRedirectCustomizer;
import io.camunda.security.spring.security.OidcResourceServerCustomizer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Provides the shared {@link ScopedApiSecurityChainBuilder} bean unconditionally. The builder is
 * required infrastructure for the always-active API security chains and must not be guarded by
 * {@code @ConditionalOnBean} — doing so would allow timing-sensitive back-off when the {@link
 * AuthFailureHandler} has not yet been registered, breaking the downstream API chains that require
 * this builder (see ADR-0008).
 *
 * <p>By resolving {@link AuthFailureHandler} as a constructor argument rather than a condition, the
 * dependency is satisfied at bean-creation time (after all definitions are registered), eliminating
 * the ordering fragility.
 */
@Configuration
public class ScopedApiSecurityChainBuilderConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public ScopedApiSecurityChainBuilder scopedApiSecurityChainBuilder(
      final CamundaSecurityLibraryProperties properties,
      final AuthFailureHandler authFailureHandler,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers) {
    return new ScopedApiSecurityChainBuilder(
        properties,
        authFailureHandler,
        pathPort,
        resourceServerCustomizers,
        corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new),
        httpsRedirectCustomizers);
  }
}
