/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.oidc;
import static io.camunda.security.spring.scope.OidcScopeRuntimeTest.withAudience;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.proxy;
import static io.camunda.security.spring.scope.ScopeRuntimeTestSupport.reloadPort;
import static io.camunda.security.spring.scope.ScopedSecurityChainReloadTest.basic;
import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import io.camunda.security.core.port.in.ScopedSecurityReloadPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.scope.ScopeRuntimeTestSupport.Sent;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.ObjectMapperConfig;
import io.camunda.security.spring.scope.ScopedSecurityChainConfigurationTest.StubUserDetailsPort;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.security.SecurityHeadersCustomizer;
import io.camunda.security.spring.user.UserConfiguration;
import jakarta.servlet.Filter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.header.HeaderWriterFilter;

/**
 * Many threads send requests to several scopes while scopes are added, replaced and removed. Every
 * answer must be the one the generation that served the request gives, no request may run filters
 * of two generations, and a removed scope must answer 404.
 */
class ScopeSwapConcurrencyTest {

  private static final Logger LOG = LoggerFactory.getLogger(ScopeSwapConcurrencyTest.class);

  private static final String STARTUP_BASIC = "/c/startup-basic";
  private static final String STARTUP_OIDC = "/c/startup-oidc";
  private static final List<String> RUNTIME_BASIC =
      List.of("/c/basic-1", "/c/basic-2", "/c/basic-3");
  private static final String RUNTIME_OIDC = "/c/runtime-oidc";
  private static final List<String> OIDC_SCOPES = List.of(STARTUP_OIDC, RUNTIME_OIDC);
  private static final Duration RUN_FOR = Duration.ofSeconds(8);
  private static final int CLIENTS = 8;

  private static final AtomicReference<List<ScopedSecurityDescriptor>> STARTUP =
      new AtomicReference<>(List.of());
  private static final AtomicInteger PROBES = new AtomicInteger();

  @Test
  void shouldServeEveryRequestFromOneGenerationWhileScopesChange() throws Exception {
    try (final var idp = MockIdentityProvider.start()) {
      STARTUP.set(
          List.of(basic(STARTUP_BASIC), withAudience(oidc(STARTUP_OIDC, idp, "app", "s"), "x")));
      runner()
          .run(
              ctx -> {
                // given
                final var port = reloadPort(ctx);
                final var proxy = proxy(ctx);
                final var world = new World(idp);
                world.record(
                    port.apply(withAudience(oidc(RUNTIME_OIDC, idp, "app", "s"), "x")), "x");
                world.audienceByGeneration.put(key(STARTUP_OIDC, 1), "x");
                final var tokenX = idp.accessToken("svc", "x");

                // when
                final var observations = run(proxy, port, world, tokenX);

                // then
                assertThat(observations.unexpected).as("unexpected answers").isEmpty();
                assertThat(observations.mixedProbes())
                    .as("chains observed with more than one generation")
                    .isEmpty();
                assertThat(observations.generationsGoingBack())
                    .as("requests served by a generation older than one already observed")
                    .isEmpty();
                assertThat(observations.requests.get()).isGreaterThan(1_000);
                assertThat(world.changes.get()).isGreaterThan(50);
                for (final var basePath : world.removed) {
                  assertThat(get(proxy, basePath + "/v2/r", null).status()).isEqualTo(404);
                  assertThat(get(proxy, basePath + "/app/x", null).status()).isEqualTo(404);
                }
                LOG.info(
                    "Concurrency run: {} requests from {} threads in {} while {} changes ran"
                        + " (outcomes {}); answers by kind {}; change latency {}",
                    observations.requests.get(),
                    CLIENTS,
                    RUN_FOR,
                    world.changes.get(),
                    world.outcomes,
                    observations.byStatus,
                    world.latencySummary());
              });
    }
  }

  private static Observations run(
      final FilterChainProxy proxy,
      final ScopedSecurityReloadPort port,
      final World world,
      final String tokenX)
      throws Exception {
    final var observations = new Observations();
    final var executor = Executors.newFixedThreadPool(CLIENTS + 1);
    final var start = new CountDownLatch(1);
    final var deadline = new AtomicLong();
    try {
      final var futures = new ArrayList<java.util.concurrent.Future<?>>();
      futures.add(
          executor.submit(
              () -> {
                start.await();
                final var random = new Random(42);
                while (System.nanoTime() < deadline.get()) {
                  world.change(port, random);
                }
                return null;
              }));
      for (int i = 0; i < CLIENTS; i++) {
        final var seed = i;
        futures.add(
            executor.submit(
                () -> {
                  start.await();
                  final var random = new Random(seed);
                  while (System.nanoTime() < deadline.get()) {
                    observations.send(proxy, world, random, tokenX);
                  }
                  return null;
                }));
      }
      deadline.set(System.nanoTime() + RUN_FOR.toNanos());
      start.countDown();
      for (final var future : futures) {
        future.get(RUN_FOR.toSeconds() + 60, TimeUnit.SECONDS);
      }
    } finally {
      executor.shutdownNow();
    }
    observations.judgeDeferred(world);
    return observations;
  }

  private static Sent get(final FilterChainProxy proxy, final String path, final String bearerToken)
      throws Exception {
    final var request = new MockHttpServletRequest("GET", path);
    if (bearerToken != null) {
      request.addHeader("Authorization", "Bearer " + bearerToken);
    }
    return ScopeRuntimeTestSupport.send(proxy, request);
  }

  private static String key(final String basePath, final long generation) {
    return basePath + "#" + generation;
  }

  private static WebApplicationContextRunner runner() {
    return new WebApplicationContextRunner()
        .withUserConfiguration(
            ObjectMapperConfig.class,
            OidcScopeRuntimeTest.Paths.class,
            StubUserDetailsPort.class,
            StartupScopes.class,
            ChainProbes.class)
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

  /** What the scopes are and were: the mutator's side of the run. */
  private static final class World {

    private final MockIdentityProvider idp;
    private final Map<String, String> audienceByGeneration = new ConcurrentHashMap<>();
    private final Set<String> removed = ConcurrentHashMap.newKeySet();
    private final AtomicInteger changes = new AtomicInteger();
    private final Map<ScopeReloadOutcome, AtomicInteger> outcomes = new ConcurrentHashMap<>();
    private final Map<ScopeReloadOutcome, List<Long>> latencyMicros = new ConcurrentHashMap<>();

    private World(final MockIdentityProvider idp) {
      this.idp = idp;
    }

    void change(final ScopedSecurityReloadPort port, final Random random) {
      final var choice = random.nextInt(6);
      if (choice < 3) {
        final var basePath = RUNTIME_BASIC.get(random.nextInt(RUNTIME_BASIC.size()));
        if (random.nextBoolean()) {
          removed.add(basePath);
          record(port.remove(basePath), null);
        } else {
          removed.remove(basePath);
          record(port.apply(basic(basePath, "PT" + (10 + random.nextInt(50)) + "S")), null);
        }
      } else if (choice < 5) {
        final var basePath = OIDC_SCOPES.get(random.nextInt(OIDC_SCOPES.size()));
        final var audience = random.nextBoolean() ? "x" : "y";
        record(port.apply(withAudience(oidc(basePath, idp, "app", "s"), audience)), audience);
      } else {
        record(port.apply(basic(STARTUP_BASIC, "PT" + (10 + random.nextInt(50)) + "S")), null);
      }
    }

    void record(final ScopeReloadResult result, final String audience) {
      assertThat(result.failure()).as("change of %s", result.basePath()).isNull();
      changes.incrementAndGet();
      outcomes.computeIfAbsent(result.outcome(), o -> new AtomicInteger()).incrementAndGet();
      latencyMicros
          .computeIfAbsent(result.outcome(), o -> new CopyOnWriteArrayList<>())
          .add(result.duration().toNanos() / 1_000);
      if (audience != null && result.applied()) {
        audienceByGeneration.put(key(result.basePath(), result.generation()), audience);
      }
    }

    String latencySummary() {
      final var summary = new StringBuilder();
      latencyMicros.forEach(
          (outcome, micros) -> {
            final var sorted = micros.stream().sorted().toList();
            summary
                .append(outcome)
                .append(": n=")
                .append(sorted.size())
                .append(" p50=")
                .append(sorted.get(sorted.size() / 2))
                .append("us p99=")
                .append(sorted.get(Math.min(sorted.size() - 1, sorted.size() * 99 / 100)))
                .append("us; ");
          });
      return summary.toString();
    }
  }

  /** What the clients saw. */
  private static final class Observations {

    private final AtomicLong requests = new AtomicLong();
    private final List<String> unexpected = new CopyOnWriteArrayList<>();
    private final Map<Integer, Set<String>> generationsByProbe = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> byStatus = new ConcurrentHashMap<>();
    private final List<BearerAnswer> bearerAnswers = new CopyOnWriteArrayList<>();
    private final Map<String, Timeline> timelines = new ConcurrentHashMap<>();

    void send(
        final FilterChainProxy proxy, final World world, final Random random, final String tokenX)
        throws Exception {
      final var all = new ArrayList<String>(RUNTIME_BASIC);
      all.add(STARTUP_BASIC);
      all.addAll(OIDC_SCOPES);
      final var basePath = all.get(random.nextInt(all.size()));
      final var oidcScope = OIDC_SCOPES.contains(basePath);
      final var kind = random.nextInt(3);
      final Sent sent;
      final String label;
      final long started = System.nanoTime();
      if (kind == 0) {
        label = oidcScope ? "oidc-bearer" : "basic-api";
        sent = get(proxy, basePath + "/v2/r", oidcScope ? tokenX : null);
      } else {
        label = oidcScope ? "oidc-webapp" : "basic-webapp";
        sent = get(proxy, basePath + "/app/x", null);
      }
      final long ended = System.nanoTime();
      requests.incrementAndGet();
      byStatus
          .computeIfAbsent(label + ":" + sent.status(), s -> new AtomicLong())
          .incrementAndGet();
      final var serving = sent.serving();
      final var probe = (Integer) sent.request().getAttribute(ChainProbes.ATTRIBUTE);
      if (serving != null && probe != null) {
        generationsByProbe
            .computeIfAbsent(probe, p -> ConcurrentHashMap.newKeySet())
            .add(key(serving.basePath(), serving.generation()));
      }
      if (serving == null) {
        expect(sent, label, sent.status() == 404 && probe == null);
        return;
      }
      expect(sent, label, serving.basePath().equals(basePath) && probe != null);
      timelines
          .computeIfAbsent(basePath, b -> new Timeline())
          .add(started, ended, serving.generation());
      switch (label) {
        case "basic-api" -> expect(sent, label, sent.status() == 401);
        case "basic-webapp" -> expect(sent, label, sent.status() == 200);
        case "oidc-webapp" -> expect(sent, label, sent.status() == 302);
        default ->
            bearerAnswers.add(
                new BearerAnswer(
                    serving.basePath(),
                    serving.generation(),
                    sent.status(),
                    sent.request().getRequestURI()));
      }
    }

    /** Bearer answers are judged once the mutator has said which audience each generation had. */
    void judgeDeferred(final World world) {
      for (final var answer : bearerAnswers) {
        final var audience =
            world.audienceByGeneration.get(key(answer.basePath(), answer.generation()));
        if (audience == null || answer.status() != ("x".equals(audience) ? 200 : 401)) {
          unexpected.add(
              "oidc-bearer "
                  + answer.uri()
                  + " -> "
                  + answer.status()
                  + " served by generation "
                  + answer.generation()
                  + " with audience "
                  + audience);
        }
      }
    }

    /**
     * Requests of a scope that started after another one ended, but were served by an older
     * generation than it: what a scope whose API and webapp chains change one after the other
     * shows.
     */
    List<String> generationsGoingBack() {
      final List<String> violations = new ArrayList<>();
      timelines.forEach(
          (basePath, timeline) -> {
            final var going = timeline.goingBack();
            if (going > 0) {
              violations.add(basePath + ": " + going);
            }
          });
      return violations;
    }

    List<String> mixedProbes() {
      return generationsByProbe.entrySet().stream()
          .filter(entry -> entry.getValue().size() > 1)
          .map(entry -> entry.getKey() + "=" + entry.getValue())
          .toList();
    }

    private void expect(final Sent sent, final String label, final boolean condition) {
      if (!condition && unexpected.size() < 20) {
        unexpected.add(
            label
                + " "
                + sent.request().getRequestURI()
                + " -> "
                + sent.status()
                + " served by "
                + sent.serving());
      }
    }
  }

  private record BearerAnswer(String basePath, long generation, int status, String uri) {}

  /** When each request of one scope started and ended, and which generation served it. */
  private static final class Timeline {

    private static final int CAPACITY = 400_000;
    private final long[] starts = new long[CAPACITY];
    private final long[] ends = new long[CAPACITY];
    private final long[] generations = new long[CAPACITY];
    private final AtomicInteger size = new AtomicInteger();

    void add(final long start, final long end, final long generation) {
      final var index = size.getAndIncrement();
      if (index < CAPACITY) {
        starts[index] = start;
        ends[index] = end;
        generations[index] = generation;
      }
    }

    /** How many requests saw an older generation than one that had ended before they started. */
    long goingBack() {
      final int count = Math.min(size.get(), CAPACITY);
      final Integer[] byEnd = new Integer[count];
      final Integer[] byStart = new Integer[count];
      for (int i = 0; i < count; i++) {
        byEnd[i] = i;
        byStart[i] = i;
      }
      java.util.Arrays.sort(byEnd, java.util.Comparator.comparingLong(i -> ends[i]));
      java.util.Arrays.sort(byStart, java.util.Comparator.comparingLong(i -> starts[i]));
      long violations = 0;
      long newestEnded = 0;
      int ended = 0;
      for (final var request : byStart) {
        while (ended < count && ends[byEnd[ended]] < starts[request]) {
          newestEnded = Math.max(newestEnded, generations[byEnd[ended]]);
          ended++;
        }
        if (generations[request] < newestEnded) {
          violations++;
        }
      }
      return violations;
    }
  }

  @Configuration
  static class StartupScopes {

    @Bean
    static CamundaSecurityScopeProvider startupScopes() {
      return STARTUP::get;
    }
  }

  /** Puts a filter with an id of its own into every chain built, to tell chains apart. */
  @Configuration
  static class ChainProbes {

    static final String ATTRIBUTE = "chain-probe";

    @Bean
    SecurityHeadersCustomizer chainProbe() {
      return http -> {
        final var id = PROBES.incrementAndGet();
        final Filter probe =
            (request, response, chain) -> {
              request.setAttribute(ATTRIBUTE, id);
              chain.doFilter(request, response);
            };
        http.addFilterAfter(probe, HeaderWriterFilter.class);
      };
    }
  }
}
