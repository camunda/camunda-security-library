/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.spi.OidcApiAuthenticationEntryPoint;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;

/**
 * Provides the default {@link OidcApiAuthenticationEntryPoint} bean. Hosts can override it by
 * registering their own {@link OidcApiAuthenticationEntryPoint} bean — the
 * {@code @ConditionalOnMissingBean} ensures the library's default backs off.
 *
 * <p>The default delegates to {@link BearerTokenAuthenticationEntryPoint}, preserving the RFC 6750
 * bearer challenge (see {@code OidcApiWwwAuthenticateChallengeTest}).
 */
@Configuration
public class OidcApiAuthenticationEntryPointConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public OidcApiAuthenticationEntryPoint oidcApiAuthenticationEntryPoint() {
    final var delegate = new BearerTokenAuthenticationEntryPoint();
    return delegate::commence;
  }
}
