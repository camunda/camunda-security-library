/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.session.WebSessionRepository;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Provides the {@link SessionRepositoryFilter} installed on the default (non-scoped) webapp and API
 * chains (ADR-0031). Unconditionally active — unlike {@code WebSessionConfiguration}, which is
 * gated on persistent sessions being enabled — because the primary chains always need a session
 * filter, exactly as every physical-tenant scope always gets one.
 *
 * <p>The backing {@link org.springframework.session.SessionRepository} follows the same preference
 * order as scoped chains: the shared durable {@link WebSessionRepository} bean (present only when
 * persistent web sessions are enabled) if available, otherwise an in-memory {@link
 * MapSessionRepository}.
 */
@Configuration
public class DefaultWebSessionFilterConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public SessionRepositoryFilter<?> defaultSessionRepositoryFilter(
      final Environment environment,
      final ObjectProvider<WebSessionRepository> webSessionRepositoryProvider) {
    final WebSessionRepository durable = webSessionRepositoryProvider.getIfAvailable();
    final SessionRepository<?> repository =
        durable != null ? durable : new MapSessionRepository(new ConcurrentHashMap<>());
    return DefaultWebSessionComponentsFactory.sessionRepositoryFilter(environment, repository);
  }
}
