/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.session;

import io.camunda.security.core.port.out.ScopedSessionStorePortProvider;
import io.camunda.security.core.port.out.SessionStorePort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.annotation.ConditionalOnPersistentWebSessionEnabled;
import io.camunda.security.spring.session.WebSessionMapper.SpringBasedWebSessionAttributeConverter;
import jakarta.servlet.http.HttpServletRequest;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.support.GenericConversionService;

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
 *
 * <p>The {@link WebSessionRepository} bean produced here is consumed directly by each chain's own
 * explicitly-installed {@code SessionRepositoryFilter} — see {@code
 * DefaultWebSessionFilterConfiguration} for the default surface and {@code
 * ScopedSecurityChainRegistrar} for physical-tenant scopes. See ADR-0009 for why filters are
 * installed per chain rather than through a single container-wide filter.
 *
 * <p>Self-registers {@link CamundaSecurityLibraryProperties} via {@link
 * EnableConfigurationProperties} so this class works when activated standalone via
 * {@code @ImportAutoConfiguration} without also importing {@code CamundaSecurityConfiguration} —
 * the same precedent {@code WebAppAuthorizationFilterConfiguration} sets for the same dependency.
 * {@code @EnableConfigurationProperties} is idempotent across configuration classes, so this has no
 * effect beyond registering the bean once when a host already imports it elsewhere.
 */
@Configuration
@ConditionalOnPersistentWebSessionEnabled
@EnableConfigurationProperties(CamundaSecurityLibraryProperties.class)
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
      final HttpServletRequest request,
      final CamundaSecurityLibraryProperties properties) {
    return new WebSessionRepository(
        sessionStorePort, webSessionMapper, request, properties.getSession());
  }

  /**
   * Factory for per-scope {@link WebSessionRepository}s, used by {@code
   * ScopedSecurityChainRegistrar} to give each scoped {@code SessionRepositoryFilter} a store bound
   * to its scope (ADR-0009). The {@link ScopedSessionStorePortProvider} is optional — when a host
   * contributes none, the factory reports {@link ScopedWebSessionRepositoryFactory#isAvailable()
   * unavailable} and scoped chains fall back to the shared {@link #webSessionRepository} or a
   * per-scope in-memory repository.
   */
  @Bean
  @ConditionalOnMissingBean
  public ScopedWebSessionRepositoryFactory scopedWebSessionRepositoryFactory(
      final ObjectProvider<ScopedSessionStorePortProvider> storePortProvider,
      final WebSessionMapper webSessionMapper,
      final HttpServletRequest request,
      final CamundaSecurityLibraryProperties properties) {
    // getIfAvailable (not getIfUnique): null when absent (→ fall back); on multiple providers it
    // resolves a @Primary if declared, otherwise throws — unprioritized ambiguity fails fast.
    return new ScopedWebSessionRepositoryFactory(
        storePortProvider.getIfAvailable(), webSessionMapper, request, properties.getSession());
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
      final ScopedWebSessionRepositoryFactory scopedWebSessionRepositoryFactory,
      final UncaughtExceptionHandler webSessionDeletionUncaughtExceptionHandler) {
    final var executor = createTaskExecutor(webSessionDeletionUncaughtExceptionHandler);
    executor.schedule(
        new SelfSchedulingTask(
            executor,
            new WebSessionDeletionTask(
                () ->
                    sweepableRepositories(webSessionRepository, scopedWebSessionRepositoryFactory)),
            WebSessionDeletionTask.DELETE_EXPIRED_SESSIONS_RUN_DELAY),
        WebSessionDeletionTask.DELETE_EXPIRED_SESSIONS_INITIAL_DELAY,
        TimeUnit.MILLISECONDS);
    return executor;
  }

  /**
   * Every distinct store the expiry sweep must clean: the default-surface repository plus each
   * per-scope one (ADR-0009). Resolved per sweep so scoped repositories created after startup are
   * included.
   */
  private static Collection<WebSessionRepository> sweepableRepositories(
      final WebSessionRepository defaultRepository,
      final ScopedWebSessionRepositoryFactory scopedWebSessionRepositoryFactory) {
    return distinctByStore(
        defaultRepository, scopedWebSessionRepositoryFactory.builtRepositories());
  }

  /**
   * Deduplicates repositories by backing {@link SessionStorePort} (identity) so each store is swept
   * once; {@code preferred} (the default-surface repository) is kept when a scope shares its store.
   * Best-effort: it collapses only repositories that share the same store <em>instance</em> — which
   * is the normal wiring when the default surface and a {@code default} scope resolve to the same
   * store.
   */
  static Collection<WebSessionRepository> distinctByStore(
      final WebSessionRepository preferred, final Collection<WebSessionRepository> others) {
    final Map<SessionStorePort, WebSessionRepository> byStore = new IdentityHashMap<>();
    byStore.put(preferred.sessionStorePort(), preferred);
    for (final WebSessionRepository repository : others) {
      byStore.putIfAbsent(repository.sessionStorePort(), repository);
    }
    return List.copyOf(byStore.values());
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
      if (!executor.isShutdown()) {
        executor.schedule(this, delay, TimeUnit.MILLISECONDS);
      }
    }
  }
}
