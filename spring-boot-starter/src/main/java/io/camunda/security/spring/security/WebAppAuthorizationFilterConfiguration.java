/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.core.port.in.AuthorizationCheckPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandlerPort;
import io.camunda.security.spring.spi.WebAppProviderPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the per-web-app authorization filter and its supporting beans. Hosts adopt by adding
 * {@code @Import(WebAppAuthorizationFilterConfiguration.class)} to their security configuration —
 * see ADR-0006 for why CSL configurations are explicitly imported rather than auto-registered.
 *
 * <p>Each bean is gated on the presence of the host SPIs it depends on, and library defaults back
 * off via {@code @ConditionalOnMissingBean} so hosts can supply their own implementations.
 *
 * <p>The webapp component-access decision is delegated to the host's {@link AuthorizationCheckPort}
 * — the same unified inbound port the data plane uses (see ADR-0017). The check honours {@code
 * camunda.security.authorizations.enabled}: when it is off, the filter passes every request through
 * without consulting the port. The flag is read from {@link CamundaSecurityLibraryProperties} (not
 * a {@code @ConditionalOnProperty}) so it works regardless of whether the host sets it via a
 * property or by mutating the bound properties bean.
 */
@Configuration
@EnableConfigurationProperties(CamundaSecurityLibraryProperties.class)
public class WebAppAuthorizationFilterConfiguration {

  /**
   * Default {@link WebAppAccessDeniedHandlerPort} that redirects to {@code
   * <contextPath>/<webApp>/forbidden}. Only registered when a {@link WebAppProviderPort} is present
   * (so the filter would otherwise have something to deny) and the host has not supplied its own
   * handler.
   */
  @Bean
  @ConditionalOnBean(WebAppProviderPort.class)
  @ConditionalOnMissingBean(WebAppAccessDeniedHandlerPort.class)
  public WebAppAccessDeniedHandlerPort webAppAccessDeniedHandler() {
    return new RedirectingWebAppAccessDeniedAdapter();
  }

  /**
   * The filter itself. Requires the host SPIs it depends on to be present — without any one of them
   * the filter has nothing meaningful to do, so it isn't created and the chain configurations skip
   * adding it via the {@link SecurityFilterChainSupport#addFilterAfterIfAvailable} helper. The
   * {@link AuthorizationCheckPort} is supplied either by the library default (see {@link
   * io.camunda.security.spring.authz.AuthorizationConfiguration}) or a host override.
   */
  @Bean
  @ConditionalOnBean({
    WebAppProviderPort.class,
    AuthorizationCheckPort.class,
    WebAppAccessDeniedHandlerPort.class,
    CamundaAuthenticationProvider.class,
    SecurityPathPort.class
  })
  public WebAppAuthorizationCheckFilter webAppAuthorizationCheckFilter(
      final WebAppProviderPort webAppProvider,
      final AuthorizationCheckPort authorizationCheckPort,
      final WebAppAccessDeniedHandlerPort webAppAccessDeniedHandler,
      final CamundaAuthenticationProvider authenticationProvider,
      final SecurityPathPort securityPathPort,
      final CamundaSecurityLibraryProperties properties) {
    return new WebAppAuthorizationCheckFilter(
        properties.getAuthorizations().isEnabled(),
        webAppProvider,
        authorizationCheckPort,
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
