/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.core.port.out.AdminUserPresencePort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.spi.AdminUserMissingHandlerPort;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the admin-user setup filter and its supporting beans. Hosts adopt by adding
 * {@code @Import(AdminUserCheckFilterConfiguration.class)} to their security configuration — see
 * ADR-0006 for why CSL configurations are explicitly imported rather than auto-registered.
 *
 * <p>Each bean is gated on the presence of the host SPIs it depends on, and library defaults back
 * off via {@code @ConditionalOnMissingBean} so hosts can supply their own implementations.
 *
 * <p>The filter is wired into the BasicAuth webapp chain only; the OIDC webapp chain intentionally
 * does not add it (see ADR-0007 and GH-189). Under OIDC, admin provisioning is driven by IdP claims
 * and mapping rules rather than an in-app setup wizard, and the filter has no signal that
 * distinguishes "no admin yet" from "this user's membership has not been projected yet" — so a
 * freshly IdP-authenticated user must not be 302'd to {@code /admin/setup}. Hosts that genuinely
 * need an admin-presence check under OIDC can inject the filter bean themselves and add it to a
 * host-owned chain.
 */
@Configuration
public class AdminUserCheckFilterConfiguration {

  /**
   * Default {@link AdminUserMissingHandlerPort} that redirects to {@code
   * <contextPath>/admin/setup}. Only registered when an {@link AdminUserPresencePort} is present
   * (so the filter would otherwise have something to deny) and the host has not supplied its own
   * handler.
   */
  @Bean
  @ConditionalOnBean(AdminUserPresencePort.class)
  @ConditionalOnMissingBean(AdminUserMissingHandlerPort.class)
  public AdminUserMissingHandlerPort adminUserMissingHandler() {
    return new RedirectingAdminUserMissingAdapter();
  }

  /**
   * The filter itself. Requires all three host SPIs to be present — without any one of them the
   * filter has nothing meaningful to do, so it isn't created and the chain configurations skip
   * adding it via the {@link SecurityFilterChainSupport#addFilterAfterIfAvailable} helper.
   */
  @Bean
  @ConditionalOnBean({
    AdminUserPresencePort.class,
    AdminUserMissingHandlerPort.class,
    SecurityPathPort.class
  })
  public AdminUserCheckFilter adminUserCheckFilter(
      final AdminUserPresencePort adminUserPresencePort,
      final AdminUserMissingHandlerPort adminUserMissingHandler,
      final SecurityPathPort securityPathPort) {
    return new AdminUserCheckFilter(
        adminUserPresencePort, adminUserMissingHandler, securityPathPort.adminFilterBypassPaths());
  }

  /**
   * Disables Spring Boot's automatic registration of {@link AdminUserCheckFilter} into the global
   * servlet filter chain. The filter is wired into the relevant Spring Security chain via {@code
   * addFilterAfter(AuthorizationFilter.class)}; without this disabling registration the filter
   * would also run for every request as a top-level servlet filter.
   */
  @Bean
  @ConditionalOnBean(AdminUserCheckFilter.class)
  public FilterRegistrationBean<AdminUserCheckFilter> adminUserCheckFilterRegistration(
      final AdminUserCheckFilter filter) {
    final var registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }
}
