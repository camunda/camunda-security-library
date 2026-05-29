/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.model.session.PersistentSession;
import io.camunda.security.core.port.out.SessionStorePort;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class WebSessionConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(WebSessionConfiguration.class))
          .withBean(SessionStorePort.class, NoopSessionStore::new);

  @Test
  void beansAreRegisteredWhenEnabled() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(WebSessionRepository.class)
                    .hasSingleBean(WebSessionMapper.class)
                    .hasSingleBean(WebSessionAttributeConverter.class)
                    .hasBean("persistentWebSessionDeletionTaskExecutor")
                    .hasBean("webSessionDeletionUncaughtExceptionHandler"));
  }

  @Test
  void beansBackOffWhenPropertyAbsent() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(WebSessionRepository.class));
  }

  @Test
  void beansBackOffWhenDisabled() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=false")
        .run(ctx -> assertThat(ctx).doesNotHaveBean(WebSessionRepository.class));
  }

  @Test
  void hostCanOverrideAttributeConverter() {
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withUserConfiguration(HostConverterConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(WebSessionAttributeConverter.class)
                    .getBean(WebSessionAttributeConverter.class)
                    .isInstanceOf(HostConverterConfiguration.HostConverter.class));
  }

  @Test
  void hostCanOverrideUncaughtExceptionHandler() {
    final UncaughtExceptionHandler hostHandler = (t, e) -> {};
    runner
        .withPropertyValues("camunda.security.session.persistent.enabled=true")
        .withBean(
            "webSessionDeletionUncaughtExceptionHandler",
            UncaughtExceptionHandler.class,
            () -> hostHandler)
        .run(
            ctx ->
                assertThat(ctx)
                    .getBean(
                        "webSessionDeletionUncaughtExceptionHandler",
                        UncaughtExceptionHandler.class)
                    .isSameAs(hostHandler));
  }

  @Configuration
  static class HostConverterConfiguration {

    @Bean
    WebSessionAttributeConverter webSessionAttributeConverter() {
      return new HostConverter();
    }

    static final class HostConverter implements WebSessionAttributeConverter {
      @Override
      public Object deserialize(final byte[] value) {
        return null;
      }

      @Override
      public byte[] serialize(final Object value) {
        return new byte[0];
      }
    }
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
