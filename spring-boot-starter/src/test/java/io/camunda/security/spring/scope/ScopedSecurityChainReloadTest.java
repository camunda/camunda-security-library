/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.ObjectMapperConfig;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.StubPaths;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.StubUserDetailsPort;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.user.UserConfiguration;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Runtime add / reconfigure / remove of scopes through {@link ScopedSecurityChainReloader}, and
 * that a removed scope leaves nothing reachable behind.
 */
class ScopedSecurityChainReloadTest {

  private static final String S1 = "/example-scope/s1";
  private static final String S2 = "/example-scope/s2";

  /** The base paths {@link MutableScopes} contributes; tests change it between reloads. */
  private static final AtomicReference<List<String>> CONTRIBUTED = new AtomicReference<>();

  @BeforeEach
  void startWithS1() {
    CONTRIBUTED.set(List.of(S1));
  }

  @AfterEach
  void reset() {
    CONTRIBUTED.set(List.of());
  }

  private static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            StubPaths.class,
            StubUserDetailsPort.class,
            MutableScopes.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                BaseSecurityConfiguration.class,
                BasicAuthApiSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                UserConfiguration.class,
                ScopedSecurityChainConfiguration.class))
        .withPropertyValues("camunda.security.authentication.method=basic");
  }

  @Test
  void addedScopeIsServedByItsOwnChain() {
    runner()
        .run(
            ctx -> {
              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(404);

              contribute(ctx, S1, S2);

              assertThat(status(ctx, S2 + "/v2/resource", null))
                  .as("the added scope must challenge instead of falling through to deny")
                  .isEqualTo(401);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void scopeCanBeAddedWhenNoneWasPresentAtStartup() {
    CONTRIBUTED.set(List.of());
    runner()
        .run(
            ctx -> {
              contribute(ctx, S2);

              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void removedAddedScopeFallsBackToTheCatchAllAgain() {
    runner()
        .run(
            ctx -> {
              contribute(ctx, S1, S2);
              contribute(ctx, S1);

              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(404);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void removedStartupScopeAnswersNotFound() {
    runner()
        .run(
            ctx -> {
              contribute(ctx);

              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(404);
            });
  }

  @Test
  void startupScopeCanComeBackAfterRemoval() {
    runner()
        .run(
            ctx -> {
              contribute(ctx);
              contribute(ctx, S1);

              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void rejectedReloadLeavesLiveScopesUntouched() {
    runner()
        .run(
            ctx -> {
              final var reloader = ctx.getBean(ScopedSecurityChainReloader.class);
              // an unsanitizable basePath makes the cookie-name validation reject the whole set
              CONTRIBUTED.set(List.of(S1, "/---"));

              assertThatThrownBy(reloader::reload).isInstanceOf(IllegalStateException.class);

              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void removedScopesChainsAndSessionFiltersAreGarbageCollected() {
    runner()
        .run(
            ctx -> {
              final List<WeakReference<Object>> released = new ArrayList<>();
              for (int i = 0; i < 5; i++) {
                contribute(ctx, S1, S2);
                released.addAll(liveReferences(ctx, S2));
                contribute(ctx, S1);
              }

              final var survivors = survivorsAfterGc(released);

              assertThat(survivors).as("still reachable after removal").isEmpty();
            });
  }

  @Test
  void reloadsDoNotGrowWhatSpringSecurityRetainsForDisposableFilters() {
    runner()
        .run(
            ctx -> {
              final var baseline = retainedDisposables(ctx);

              for (int i = 0; i < 5; i++) {
                contribute(ctx, S1, S2); // adds a scope and rebuilds S1
                contribute(ctx, S1); // removes the added scope
              }

              assertThat(retainedDisposables(ctx))
                  .as("filters of replaced or removed chains must be released")
                  .hasSameSizeAs(baseline);
            });
  }

  private static void contribute(final ApplicationContext ctx, final String... basePaths) {
    CONTRIBUTED.set(List.of(basePaths));
    ctx.getBean(ScopedSecurityChainReloader.class).reload();
  }

  /** Weak references to the chains, their filters and the session filter serving the scope. */
  private static List<WeakReference<Object>> liveReferences(
      final ApplicationContext ctx, final String basePath) {
    final var probe = new MockHttpServletRequest("GET", basePath + "/v2/resource");
    final List<WeakReference<Object>> references = new ArrayList<>();
    final var scoped =
        chains(ctx).stream()
            .filter(
                c ->
                    c instanceof DynamicScopedSecurityFilterChain
                        || c instanceof OrderedSecurityFilterChainWrapper)
            .filter(c -> c.matches(probe))
            .toList();
    for (final var chain : scoped) {
      final var live = liveChain(chain, probe);
      references.add(new WeakReference<>(live));
      live.getFilters().forEach(filter -> references.add(new WeakReference<>(filter)));
    }
    return references;
  }

  private static SecurityFilterChain liveChain(
      final SecurityFilterChain chain, final MockHttpServletRequest probe) {
    if (chain instanceof DynamicScopedSecurityFilterChain dynamic) {
      return dynamic.chains().values().stream().filter(c -> c.matches(probe)).findFirst().get();
    }
    final var wrapper = (OrderedSecurityFilterChainWrapper) chain;
    return wrapper.delegate();
  }

  private static List<String> survivorsAfterGc(final List<WeakReference<Object>> references) {
    for (int attempt = 0; attempt < 50 && !survivors(references).isEmpty(); attempt++) {
      System.gc();
      try {
        Thread.sleep(50);
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    return survivors(references);
  }

  private static List<String> survivors(final List<WeakReference<Object>> references) {
    return references.stream()
        .map(WeakReference::get)
        .filter(Objects::nonNull)
        .map(object -> object.getClass().getName())
        .toList();
  }

  /** What Spring Security's shared ObjectPostProcessor keeps alive until the context closes. */
  private static List<Object> retainedDisposables(final ApplicationContext ctx)
      throws ReflectiveOperationException {
    final var processor =
        ctx.getBeanProvider(
                ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, Object.class))
            .getObject();
    final var field = processor.getClass().getDeclaredField("disposableBeans");
    field.setAccessible(true);
    return new ArrayList<>((List<?>) field.get(processor));
  }

  private static List<SecurityFilterChain> chains(final ApplicationContext ctx) {
    final var chains = new ArrayList<>(ctx.getBeansOfType(SecurityFilterChain.class).values());
    chains.sort(AnnotationAwareOrderComparator.INSTANCE);
    return chains;
  }

  /** Sends a request through all registered chains the way the servlet container would. */
  private static int status(final ApplicationContext ctx, final String path, final String auth)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", path);
    if (auth != null) {
      request.addHeader("Authorization", auth);
    }
    final var response = new MockHttpServletResponse();
    final var proxy = new FilterChainProxy(chains(ctx));
    final var next = new MockFilterChain();
    proxy.doFilter(request, response, next);
    // no chain matched: the catch-all deny chain of a real host answers 404
    return next.getRequest() != null ? 404 : response.getStatus();
  }

  @Configuration
  static class MutableScopes {

    @Bean
    static CamundaSecurityScopeProvider mutableScopeProvider() {
      final var auth = new AuthenticationConfiguration();
      auth.setMethod(AuthenticationMethod.BASIC);
      return () ->
          CONTRIBUTED.get().stream()
              .map(basePath -> new ScopedSecurityDescriptor(basePath, auth))
              .toList();
    }
  }
}
