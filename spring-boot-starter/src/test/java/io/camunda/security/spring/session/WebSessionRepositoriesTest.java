/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.config.SessionConfiguration;
import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.session.MapSessionRepository;

class WebSessionRepositoriesTest {

  @Test
  void returnsTheDurableRepositoryWhenPresent() {
    final var durable =
        new WebSessionRepository(
            new NoopSessionStore(),
            new WebSessionMapper(
                new WebSessionMapper.SpringBasedWebSessionAttributeConverter(
                    new org.springframework.core.convert.support.GenericConversionService())),
            new MockHttpServletRequest(),
            new SessionConfiguration());

    assertThat(
            WebSessionRepositories.durableOrInMemory(
                durable, new SessionConfiguration(), "default"))
        .isSameAs(durable);
  }

  @Test
  void fallsBackToInMemoryRepositoryWhenDurableIsAbsent() {
    assertThat(
            WebSessionRepositories.durableOrInMemory(null, new SessionConfiguration(), "default"))
        .isInstanceOf(MapSessionRepository.class);
  }

  @Test
  void appliesConfiguredIntervalToInMemoryFallback() {
    final var sessionConfiguration = new SessionConfiguration();
    sessionConfiguration.setMaxInactiveInterval(Duration.ofMinutes(45));

    final var repository =
        (MapSessionRepository)
            WebSessionRepositories.durableOrInMemory(null, sessionConfiguration, "default");

    final var session = repository.createSession();
    assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofMinutes(45));
  }

  @Test
  void warnsWhenHeartbeatEnabledHasNoEffectOnInMemoryFallback() {
    final var sessionConfiguration = new SessionConfiguration();
    sessionConfiguration.getHeartbeat().setEnabled(true);

    final var appender = attachAppender();
    try {
      WebSessionRepositories.durableOrInMemory(null, sessionConfiguration, "/physical-tenants/t1");
    } finally {
      detachAppender(appender);
    }

    assertThat(appender.list)
        .anySatisfy(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage())
                  .contains("heartbeat.enabled=true has no effect")
                  .contains("/physical-tenants/t1");
            });
  }

  @Test
  void doesNotWarnWhenHeartbeatDisabled() {
    final var appender = attachAppender();
    try {
      WebSessionRepositories.durableOrInMemory(null, new SessionConfiguration(), "default");
    } finally {
      detachAppender(appender);
    }

    assertThat(appender.list).isEmpty();
  }

  @Test
  void doesNotWarnWhenHeartbeatEnabledButDurableRepositoryIsPresent() {
    final var sessionConfiguration = new SessionConfiguration();
    sessionConfiguration.getHeartbeat().setEnabled(true);
    final var durable =
        new WebSessionRepository(
            new NoopSessionStore(),
            new WebSessionMapper(
                new WebSessionMapper.SpringBasedWebSessionAttributeConverter(
                    new org.springframework.core.convert.support.GenericConversionService())),
            new MockHttpServletRequest(),
            sessionConfiguration);

    final var appender = attachAppender();
    try {
      WebSessionRepositories.durableOrInMemory(durable, sessionConfiguration, "default");
    } finally {
      detachAppender(appender);
    }

    assertThat(appender.list).isEmpty();
  }

  private static ListAppender<ILoggingEvent> attachAppender() {
    final Logger logger = (Logger) LoggerFactory.getLogger(WebSessionRepositories.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);
    return appender;
  }

  private static void detachAppender(final ListAppender<ILoggingEvent> appender) {
    final Logger logger = (Logger) LoggerFactory.getLogger(WebSessionRepositories.class);
    logger.detachAppender(appender);
    appender.stop();
  }

  private static final class NoopSessionStore implements SessionStorePort {
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
