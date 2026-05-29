/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.annotation.ConditionalOnPersistentWebSessionEnabled;
import io.camunda.security.spring.session.WebSessionMapper.SpringBasedWebSessionAttributeConverter;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

/**
 * Wires the persistent web-session lifecycle: the Spring Session {@link WebSessionRepository}, its
 * mapper and attribute converter, and the scheduled task that evicts expired sessions. The
 * repository persists through the host-supplied {@link SessionStorePort} bean.
 *
 * <p>This configuration is <strong>not</strong> auto-activated. Hosts must {@code @Import} it
 * (typically behind their own web/gateway condition) and supply a {@link SessionStorePort}. It is
 * gated by {@link ConditionalOnPersistentWebSessionEnabled} ({@code
 * camunda.security.session.persistent.enabled=true}). Every bean is {@link
 * ConditionalOnMissingBean} so hosts can override individual pieces — for example the {@code
 * webSessionDeletionUncaughtExceptionHandler} to plug in their own fatal-error handling.
 */
@Configuration
@EnableSpringHttpSession
@ConditionalOnPersistentWebSessionEnabled
public class WebSessionConfiguration {

  private static final Logger LOGGER = LoggerFactory.getLogger(WebSessionConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public WebSessionAttributeConverter webSessionAttributeConverter() {
    return new SpringBasedWebSessionAttributeConverter(new GenericConversionService());
  }

  @Bean
  @ConditionalOnMissingBean
  public WebSessionMapper webSessionMapper(final WebSessionAttributeConverter converter) {
    return new WebSessionMapper(converter);
  }

  @Bean
  @ConditionalOnMissingBean
  public WebSessionRepository webSessionRepository(
      final SessionStorePort sessionStorePort,
      final WebSessionMapper webSessionMapper,
      final HttpServletRequest request) {
    return new WebSessionRepository(sessionStorePort, webSessionMapper, request);
  }

  @Bean
  @ConditionalOnMissingBean(name = "webSessionDeletionUncaughtExceptionHandler")
  public UncaughtExceptionHandler webSessionDeletionUncaughtExceptionHandler() {
    return (thread, throwable) ->
        LOGGER.error(
            "Uncaught exception in web session deletion thread {}", thread.getName(), throwable);
  }

  @Bean("persistentWebSessionDeletionTaskExecutor")
  @ConditionalOnMissingBean(name = "persistentWebSessionDeletionTaskExecutor")
  public ScheduledThreadPoolExecutor persistentWebSessionDeletionTaskExecutor(
      final WebSessionRepository webSessionRepository,
      final UncaughtExceptionHandler webSessionDeletionUncaughtExceptionHandler) {
    final var executor = createTaskExecutor(webSessionDeletionUncaughtExceptionHandler);
    executor.schedule(
        new SelfSchedulingTask(
            executor,
            new WebSessionDeletionTask(webSessionRepository),
            WebSessionDeletionTask.DELETE_EXPIRED_SESSIONS_RUN_DELAY),
        WebSessionDeletionTask.DELETE_EXPIRED_SESSIONS_INITIAL_DELAY,
        TimeUnit.MILLISECONDS);
    return executor;
  }

  private static ScheduledThreadPoolExecutor createTaskExecutor(
      final UncaughtExceptionHandler uncaughtExceptionHandler) {
    final var threadFactory =
        Thread.ofPlatform()
            .name("camunda-web-session-deletion-", 0)
            .uncaughtExceptionHandler(uncaughtExceptionHandler)
            .factory();
    final var executor = new ScheduledThreadPoolExecutor(0, threadFactory);
    executor.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
    executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
    executor.setRemoveOnCancelPolicy(true);
    executor.allowCoreThreadTimeOut(true);
    executor.setKeepAliveTime(1, TimeUnit.MINUTES);
    executor.setCorePoolSize(1);
    return executor;
  }

  static final class SelfSchedulingTask implements Runnable {

    private final ScheduledThreadPoolExecutor executor;
    private final Runnable task;
    private final long delay;

    SelfSchedulingTask(
        final ScheduledThreadPoolExecutor executor, final Runnable task, final long delay) {
      this.executor = executor;
      this.task = task;
      this.delay = delay;
    }

    @Override
    public void run() {
      task.run();
      executor.schedule(this, delay, TimeUnit.MILLISECONDS);
    }
  }
}
