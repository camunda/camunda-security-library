/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.session.WebSessionRepositories;
import io.camunda.security.spring.session.WebSessionRepository;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Provides the {@link SessionRepositoryFilter} installed on the default (non-scoped) webapp and API
 * chains (ADR-0031). Always active: the primary chains always need a session filter, exactly as
 * every physical-tenant scope always gets one.
 *
 * <p>The backing {@link org.springframework.session.SessionRepository} follows the same preference
 * order as scoped chains: the shared durable {@link WebSessionRepository} bean (present only when
 * persistent web sessions are enabled) if available, otherwise an in-memory {@link
 * MapSessionRepository}.
 *
 * <p>Self-registers {@link CamundaSecurityLibraryProperties} via {@link
 * EnableConfigurationProperties} so this class works when a host {@code @Import}s it standalone,
 * without also importing {@code CamundaSecurityConfiguration} — the same precedent {@code
 * WebAppAuthorizationFilterConfiguration} sets for the same dependency.
 * {@code @EnableConfigurationProperties} is idempotent across configuration classes, so this has no
 * effect beyond registering the bean once when a host already imports it elsewhere.
 */
@Configuration
@EnableConfigurationProperties(CamundaSecurityLibraryProperties.class)
public class DefaultWebSessionFilterConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public SessionRepositoryFilter<?> defaultSessionRepositoryFilter(
      final Environment environment,
      final ObjectProvider<WebSessionRepository> webSessionRepositoryProvider,
      final CamundaSecurityLibraryProperties properties) {
    final var repository =
        WebSessionRepositories.durableOrInMemory(
            webSessionRepositoryProvider.getIfAvailable(), properties.getSession(), "default");
    return DefaultWebSessionComponentsFactory.sessionRepositoryFilter(environment, repository);
  }

  /**
   * {@code defaultSessionRepositoryFilter} is itself a servlet {@link jakarta.servlet.Filter} bean,
   * so without this Spring Boot would auto-register it as a container-wide filter — in addition to
   * its explicit per-chain installation via {@code addFilterBefore(SecurityContextHolderFilter)} —
   * reintroducing exactly the nested-filter, shared-request-attribute interference ADR-0031
   * removes. Mirrors {@code AdminUserCheckFilterConfiguration} / {@code
   * WebAppAuthorizationFilterConfiguration}.
   */
  @Bean
  public FilterRegistrationBean<Filter> defaultSessionRepositoryFilterRegistration(
      final SessionRepositoryFilter<?> defaultSessionRepositoryFilter) {
    final FilterRegistrationBean<Filter> registration =
        new FilterRegistrationBean<>(defaultSessionRepositoryFilter);
    registration.setEnabled(false);
    return registration;
  }
}
