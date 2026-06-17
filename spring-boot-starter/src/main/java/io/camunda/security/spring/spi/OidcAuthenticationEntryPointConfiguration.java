/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * Provides the default {@link OidcAuthenticationEntryPoint} bean. Hosts can override it by
 * registering their own {@link OidcAuthenticationEntryPoint} bean — the
 * {@code @ConditionalOnMissingBean} ensures the library's default backs off.
 *
 * <p>This configuration is not imported by {@link
 * io.camunda.security.spring.CamundaSecurityAutoConfiguration}; it is picked up once the {@code
 * OidcJwtCookieWebappSecurityConfiguration} imports it.
 */
@Configuration
public class OidcAuthenticationEntryPointConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public OidcAuthenticationEntryPoint oidcAuthenticationEntryPoint() {
    final var delegate = new LoginUrlAuthenticationEntryPoint("/login");
    return delegate::commence;
  }
}
