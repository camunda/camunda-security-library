/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.assertCollected;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.generation;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.reloadPort;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.slots;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.status;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadReport;
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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Runtime add / reconfigure / remove of BASIC scopes through {@link
 * io.camunda.security.core.port.in.ScopedSecurityReloadPort}, and that a retired generation leaves
 * nothing reachable behind.
 */
class ScopedSecurityChainReloadTest {

  static final String S1 = "/example-scope/s1";
  static final String S2 = "/example-scope/s2";

  /** The descriptors {@link MutableScopes} contributes; tests change it between reloads. */
  private static final AtomicReference<List<ScopedSecurityDescriptor>> CONTRIBUTED =
      new AtomicReference<>();

  @BeforeEach
  void startWithS1() {
    CONTRIBUTED.set(List.of(basic(S1)));
  }

  @AfterEach
  void reset() {
    CONTRIBUTED.set(List.of());
  }

  static WebApplicationContextRunner runner() {
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
  void shouldServeAScopeAddedByReloadingAll() {
    runner()
        .run(
            ctx -> {
              // given
              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(404);

              // when
              final var report = contribute(ctx, basic(S1), basic(S2));

              // then
              assertThat(report.result(S2).orElseThrow().outcome())
                  .isEqualTo(ScopeReloadOutcome.ADDED);
              assertThat(report.result(S1).orElseThrow().outcome())
                  .isEqualTo(ScopeReloadOutcome.UNCHANGED);
              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(401);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldServeAScopeAddedWhenNoneWasPresentAtStartup() {
    CONTRIBUTED.set(List.of());
    runner()
        .run(
            ctx -> {
              // when
              final var result = reloadPort(ctx).apply(basic(S2));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.ADDED);
              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldAnswerNotFoundForARemovedRuntimeScope() {
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(basic(S2));

              // when
              final var result = reloadPort(ctx).remove(S2);

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REMOVED);
              assertThat(status(ctx, S2 + "/v2/resource", null)).isEqualTo(404);
              assertThat(status(ctx, S2 + "/any/other/path", null)).isEqualTo(404);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldAnswerNotFoundForARemovedStartupScope() {
    runner()
        .run(
            ctx -> {
              // when
              final var report = contribute(ctx);

              // then
              assertThat(report.result(S1).orElseThrow().outcome())
                  .isEqualTo(ScopeReloadOutcome.REMOVED);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(404);
            });
  }

  @Test
  void shouldServeAStartupScopeAddedAgainAfterRemoval() {
    runner()
        .run(
            ctx -> {
              // given
              contribute(ctx);

              // when
              final var report = contribute(ctx, basic(S1));

              // then
              assertThat(report.result(S1).orElseThrow().outcome())
                  .isEqualTo(ScopeReloadOutcome.ADDED);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldReportAnAbsentScopeWhenRemovingOneThatIsNotServed() {
    runner()
        .run(
            ctx -> {
              // when
              final var result = reloadPort(ctx).remove("/never/served");

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.ABSENT);
            });
  }

  @Test
  void shouldRejectAnInvalidSetAndLeaveLiveScopesUntouched() {
    runner()
        .run(
            ctx -> {
              // given
              final var before = generation(ctx, S1);
              CONTRIBUTED.set(List.of(basic(S1), basic("/---")));

              // when / then
              assertThatThrownBy(() -> reloadPort(ctx).reloadAll())
                  .isInstanceOf(IllegalStateException.class);
              assertThat(generation(ctx, S1)).isSameAs(before);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldKeepTheLiveGenerationWhenTheNextOneFailsToBuild() {
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(basic(S2));
              final var s1Before = generation(ctx, S1);
              final var s2Before = generation(ctx, S2);

              // when
              final var result = reloadPort(ctx).apply(oidcWithoutProviders(S1));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.FAILED);
              assertThat(result.failure()).isNotNull();
              assertThat(generation(ctx, S1)).isSameAs(s1Before);
              assertThat(generation(ctx, S2)).isSameAs(s2Before);
              assertThat(status(ctx, S1 + "/v2/resource", null)).isEqualTo(401);
            });
  }

  @Test
  void shouldRebuildOnlyTheScopeThatChanged() {
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(basic(S2));
              final var s1Before = generation(ctx, S1);
              final var s2Before = generation(ctx, S2);

              // when
              final var result = reloadPort(ctx).apply(basic(S2, "PT45S"));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.REPLACED);
              assertThat(result.generation()).isGreaterThan(s2Before.number());
              assertThat(generation(ctx, S1)).isSameAs(s1Before);
              assertThat(generation(ctx, S2)).isNotSameAs(s2Before);
            });
  }

  @Test
  void shouldNotRebuildAnUnchangedScope() {
    runner()
        .run(
            ctx -> {
              // given
              final var before = generation(ctx, S1);

              // when
              final var result = reloadPort(ctx).apply(basic(S1));

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.UNCHANGED);
              assertThat(generation(ctx, S1)).isSameAs(before);
            });
  }

  @Test
  void shouldReleaseEveryRetiredGeneration() {
    runner()
        .run(
            ctx -> {
              // given
              final List<WeakReference<Object>> retired = new ArrayList<>();

              // when
              for (int i = 0; i < 10; i++) {
                retired.addAll(references(generation(ctx, S1)));
                reloadPort(ctx).apply(basic(S1, "PT" + (10 + i) + "S")).orThrow();
                reloadPort(ctx).apply(basic(S2)).orThrow();
                retired.addAll(references(generation(ctx, S2)));
                reloadPort(ctx).remove(S2).orThrow();
              }

              // then
              assertCollected(retired);
            });
  }

  @Test
  void shouldOwnWhatSpringSecurityPostProcessedForTheScope() {
    runner()
        .run(
            ctx -> {
              // when
              final var generation = generation(ctx, S1);

              // then
              assertThat(generation.objects().processedCount()).isPositive();
              assertThat(generation.objects().disposableCount()).isPositive();
            });
  }

  @Test
  void shouldReleaseTheSessionStateOfARemovedScope() {
    runner()
        .run(
            ctx -> {
              // given
              reloadPort(ctx).apply(basic(S2)).orThrow();
              final var references = sessionFilterOf(generation(ctx, S2));

              // when
              reloadPort(ctx).remove(S2).orThrow();

              // then
              assertCollected(references);
            });
  }

  @Test
  void shouldRejectARotationThatChangesMoreThanCredentials() {
    runner()
        .run(
            ctx -> {
              // given
              final var before = generation(ctx, S1);

              // when / then
              assertThatThrownBy(() -> reloadPort(ctx).rotateCredentials(basic(S1, "PT99S")))
                  .isInstanceOf(IllegalArgumentException.class);
              assertThat(generation(ctx, S1)).isSameAs(before);
            });
  }

  @Test
  void shouldRejectARotationOfAScopeThatIsNotServed() {
    runner()
        .run(
            ctx ->
                // when / then
                assertThatThrownBy(() -> reloadPort(ctx).rotateCredentials(basic(S2)))
                    .isInstanceOf(IllegalArgumentException.class));
  }

  @Test
  void shouldRebuildAScopeWhoseCredentialsAreRefreshed() {
    runner()
        .run(
            ctx -> {
              // given
              final var before = generation(ctx, S1);

              // when
              final var result = reloadPort(ctx).refreshCredentials(S1);

              // then
              assertThat(result.outcome()).isEqualTo(ScopeReloadOutcome.CREDENTIALS_REFRESHED);
              assertThat(generation(ctx, S1).number()).isGreaterThan(before.number());
              assertThat(reloadPort(ctx).refreshCredentials(S2).outcome())
                  .isEqualTo(ScopeReloadOutcome.ABSENT);
            });
  }

  @Test
  void shouldRejectAScopeWhoseCookieNameCollidesWithAServedOne() {
    runner()
        .run(
            ctx ->
                // when / then
                assertThatThrownBy(() -> reloadPort(ctx).apply(basic("/example-scope-s1")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining(S1));
  }

  @Test
  void shouldKeepOneSlotPerBasePathAcrossChanges() {
    runner()
        .run(
            ctx -> {
              // when
              for (int i = 0; i < 25; i++) {
                reloadPort(ctx).apply(basic(S2));
                reloadPort(ctx).remove(S2);
              }

              // then
              assertThat(slots(ctx).all()).hasSize(2);
            });
  }

  /** The generation, its chains and every filter they run except the scope's session filter. */
  private static List<WeakReference<Object>> references(final ScopeGeneration generation) {
    final List<Object> objects = new ArrayList<>();
    objects.add(generation);
    objects.add(generation.api());
    objects.add(generation.webapp());
    objects.addAll(generation.api().getFilters());
    objects.addAll(generation.webapp().getFilters());
    objects.removeIf(SessionRepositoryFilter.class::isInstance);
    return ScopeRuntimeTestSupport.weakly(objects);
  }

  private static List<WeakReference<Object>> sessionFilterOf(final ScopeGeneration generation) {
    return ScopeRuntimeTestSupport.weakly(
        generation.api().getFilters().stream()
            .filter(SessionRepositoryFilter.class::isInstance)
            .toList());
  }

  private static ScopeReloadReport contribute(
      final ApplicationContext ctx, final ScopedSecurityDescriptor... descriptors) {
    CONTRIBUTED.set(List.of(descriptors));
    return reloadPort(ctx).reloadAll();
  }

  static ScopedSecurityDescriptor basic(final String basePath) {
    return basic(basePath, "PT30S");
  }

  /** A BASIC scope; the refresh interval stands in for any authentication-relevant setting. */
  static ScopedSecurityDescriptor basic(final String basePath, final String refreshInterval) {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.BASIC);
    auth.setAuthenticationRefreshInterval(refreshInterval);
    return new ScopedSecurityDescriptor(basePath, auth);
  }

  private static ScopedSecurityDescriptor oidcWithoutProviders(final String basePath) {
    final var auth = new AuthenticationConfiguration();
    auth.setMethod(AuthenticationMethod.OIDC);
    return new ScopedSecurityDescriptor(basePath, auth);
  }

  @Configuration
  static class MutableScopes {

    @Bean
    static CamundaSecurityScopeProvider mutableScopeProvider() {
      return CONTRIBUTED::get;
    }
  }
}
