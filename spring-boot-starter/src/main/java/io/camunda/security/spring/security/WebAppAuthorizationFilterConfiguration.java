/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.core.port.in.ResourcePermissionPort;
import io.camunda.security.core.port.out.AuthorizationRepositoryPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandler;
import io.camunda.security.spring.spi.WebAppProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the per-web-app authorization filter and its supporting beans. Hosts adopt by adding
 * {@code @Import(WebAppAuthorizationFilterConfiguration.class)} to their security configuration —
 * see ADR-0008 for why CSL configurations are explicitly imported rather than auto-registered.
 *
 * <p>Each bean is gated on the presence of the host SPIs it depends on, and library defaults back
 * off via {@code @ConditionalOnMissingBean} so hosts can supply their own implementations.
 */
@Configuration
public class WebAppAuthorizationFilterConfiguration {

  /**
   * Default {@link ResourcePermissionPort} that consults the host's authorization records via
   * {@link AuthorizationRepositoryPort}. Skipped when the host provides its own {@code
   * ResourcePermissionPort} bean or has not registered an {@code AuthorizationRepositoryPort} yet.
   */
  @Bean
  @ConditionalOnBean(AuthorizationRepositoryPort.class)
  @ConditionalOnMissingBean(ResourcePermissionPort.class)
  public ResourcePermissionService resourcePermissionService(
      final AuthorizationRepositoryPort authorizationRepository) {
    return new ResourcePermissionService(authorizationRepository);
  }

  /**
   * Default {@link WebAppAccessDeniedHandler} that redirects to {@code
   * <contextPath>/<webApp>/forbidden}. Only registered when a {@link WebAppProvider} is present (so
   * the filter would otherwise have something to deny) and the host has not supplied its own
   * handler.
   */
  @Bean
  @ConditionalOnBean(WebAppProvider.class)
  @ConditionalOnMissingBean(WebAppAccessDeniedHandler.class)
  public WebAppAccessDeniedHandler webAppAccessDeniedHandler() {
    return new RedirectingWebAppAccessDeniedHandler();
  }

  /**
   * The filter itself. Requires all three host SPIs to be present — without any one of them the
   * filter has nothing meaningful to do, so it isn't created and the chain configurations skip
   * adding it via the {@link SecurityFilterChainSupport#addFilterAfterIfAvailable} helper.
   */
  @Bean
  @ConditionalOnBean({
    WebAppProvider.class,
    ResourcePermissionPort.class,
    CamundaAuthenticationProvider.class
  })
  public WebAppAuthorizationCheckFilter webAppAuthorizationCheckFilter(
      final WebAppProvider webAppProvider,
      final ResourcePermissionPort resourcePermissionPort,
      final WebAppAccessDeniedHandler webAppAccessDeniedHandler,
      final CamundaAuthenticationProvider authenticationProvider,
      final SecurityPathPort securityPathPort) {
    return new WebAppAuthorizationCheckFilter(
        webAppProvider,
        resourcePermissionPort,
        webAppAccessDeniedHandler,
        authenticationProvider,
        securityPathPort.staticResourceSuffixes());
  }

  /**
   * Disables Spring Boot's automatic registration of {@link WebAppAuthorizationCheckFilter} into
   * the global servlet filter chain. The filter is wired into the relevant Spring Security chain
   * via {@code addFilterAfter(AuthorizationFilter.class)}; without this disabling registration the
   * filter would also run for every request as a top-level servlet filter.
   */
  @Bean
  @ConditionalOnBean(WebAppAuthorizationCheckFilter.class)
  public FilterRegistrationBean<WebAppAuthorizationCheckFilter>
      webAppAuthorizationCheckFilterRegistration(final WebAppAuthorizationCheckFilter filter) {
    final var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }
}
