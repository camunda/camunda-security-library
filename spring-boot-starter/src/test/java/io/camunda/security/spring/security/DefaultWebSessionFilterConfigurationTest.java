/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.session.WebSessionConfiguration;
import io.camunda.security.spring.session.WebSessionRepository;
import io.camunda.security.spring.session.WebSessionTestAccess;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies the {@code defaultSessionRepositoryFilter} bean's repository resolution (ADR-0031):
 * falls back to an in-memory {@link MapSessionRepository} when persistent web sessions are
 * disabled, and uses the durable {@link WebSessionRepository} bean when they are enabled — the same
 * preference order {@code ScopedSecurityChainRegistrar} applies for scoped chains.
 *
 * <p>The runner imports only {@link DefaultWebSessionFilterConfiguration} — deliberately not {@code
 * CamundaSecurityConfiguration} — matching how a host adopts it standalone per CSL's
 * explicit-import model. This exercises {@code @EnableConfigurationProperties} on the class itself
 * rather than routing around that requirement via a broader import.
 */
class DefaultWebSessionFilterConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(DefaultWebSessionFilterConfiguration.class));

  @Test
  void fallsBackToMapSessionRepositoryWhenPersistenceDisabled() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(SessionRepositoryFilter.class);
          final var filter = ctx.getBean(SessionRepositoryFilter.class);
          assertThat(sessionRepository(filter)).isInstanceOf(MapSessionRepository.class);
        });
  }

  @Test
  void appliesConfiguredMaxInactiveIntervalToInMemoryFallback() {
    runner
        .withPropertyValues("camunda.security.session.max-inactive-interval=45m")
        .run(
            ctx -> {
              final var filter = ctx.getBean(SessionRepositoryFilter.class);
              final var repository = (MapSessionRepository) sessionRepository(filter);
              assertThat(repository.createSession().getMaxInactiveInterval())
                  .isEqualTo(java.time.Duration.ofMinutes(45));
            });
  }

  @Test
  void usesTheDurableWebSessionRepositoryWhenPersistenceEnabled() {
    runner
        .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
        .withBean(SessionStorePort.class, NoopSessionStore::new)
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(SessionRepositoryFilter.class);
              final var filter = ctx.getBean(SessionRepositoryFilter.class);
              assertThat(sessionRepository(filter))
                  .as("must reuse the durable WebSessionRepository bean, not a fresh in-memory one")
                  .isSameAs(ctx.getBean(WebSessionRepository.class));
            });
  }

  @Test
  void backsOffWhenHostSuppliesItsOwnSessionRepositoryFilter() {
    final var hostFilter =
        new SessionRepositoryFilter<>(new MapSessionRepository(new ConcurrentHashMap<>()));
    runner
        .withBean(SessionRepositoryFilter.class, () -> hostFilter)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(SessionRepositoryFilter.class)
                    .getBean(SessionRepositoryFilter.class)
                    .isSameAs(hostFilter));
  }

  @Test
  void filterRegistrationIsDisabledSoSpringBootDoesNotAutoRegisterItGlobally() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(FilterRegistrationBean.class);
          final FilterRegistrationBean<?> registration = ctx.getBean(FilterRegistrationBean.class);
          assertThat(registration.isEnabled())
              .as(
                  "must be disabled — otherwise Spring Boot auto-registers the filter as a"
                      + " container-wide filter, reintroducing ADR-0031's nested-filter bug")
              .isFalse();
        });
  }

  private static SessionRepository<?> sessionRepository(final SessionRepositoryFilter<?> filter) {
    return WebSessionTestAccess.repositoryOf(filter);
  }

  static final class NoopSessionStore implements SessionStorePort {
    @Override
    public PersistentSession get(final String sessionId) {
      return null;
    }

    @Override
    public void upsert(final PersistentSession session) {}

    @Override
    public void delete(final String sessionId) {}

    @Override
    public List<PersistentSession> getAll() {
      return List.of();
    }
  }
}
