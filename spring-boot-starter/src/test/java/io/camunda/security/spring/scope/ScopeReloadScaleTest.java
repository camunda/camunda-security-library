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

import io.camunda.security.api.model.scope.ScopeReloadOutcome;
import io.camunda.security.api.model.scope.ScopeReloadResult;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.FilterChainProxy;

/**
 * Serves a thousand scopes added at runtime and measures what one change and one request cost. The
 * measurements are logged; the assertions are about behaviour only, so the test does not depend on
 * the speed of the machine.
 */
class ScopeReloadScaleTest {

  private static final Logger LOG = LoggerFactory.getLogger(ScopeReloadScaleTest.class);
  private static final int SCOPES = 1_000;
  private static final int OIDC_SCOPES = 100;

  @Test
  void shouldServeAThousandRuntimeScopes() throws Exception {
    try (final var idp = MockIdentityProvider.start()) {
      OidcScopeRuntimeTest.runner()
          .run(
              ctx -> {
                // given
                final var port = reloadPort(ctx);
                final var proxy = proxy(ctx);
                final var heapBefore = usedHeap();

                // when
                final var basicAdds = measure(SCOPES, i -> port.apply(basic(scope(i))));
                final var heapAfter = usedHeap();
                final var oidcAdds =
                    measure(
                        OIDC_SCOPES,
                        i -> port.apply(withAudience(oidc(oidcScope(i), idp, "app", "s"), "a")));
                final var oidcReplaces =
                    measure(
                        OIDC_SCOPES,
                        i -> port.apply(withAudience(oidc(oidcScope(i), idp, "app", "s"), "b")));
                final var basicReplaces =
                    measure(SCOPES, i -> port.apply(basic(scope(i), "PT45S")));
                final var unchanged = measure(SCOPES, i -> port.apply(basic(scope(i), "PT45S")));
                final var removes = measure(SCOPES, i -> port.remove(scope(i)));
                final var requestNanos = requestCost(proxy, idp);

                // then
                assertThat(basicAdds.outcomes()).containsOnly(ScopeReloadOutcome.ADDED);
                assertThat(oidcReplaces.outcomes()).containsOnly(ScopeReloadOutcome.REPLACED);
                assertThat(basicReplaces.outcomes()).containsOnly(ScopeReloadOutcome.REPLACED);
                assertThat(unchanged.outcomes()).containsOnly(ScopeReloadOutcome.UNCHANGED);
                assertThat(removes.outcomes()).containsOnly(ScopeReloadOutcome.REMOVED);
                LOG.info(
                    "Scale run: BASIC add {}; BASIC replace {}; unchanged {}; remove {};"
                        + " OIDC add {}; OIDC replace (incl. provider check) {};"
                        + " ~{} KiB heap per BASIC scope; request through the dispatcher with"
                        + " {} scopes served: median {} us",
                    basicAdds,
                    basicReplaces,
                    unchanged,
                    removes,
                    oidcAdds,
                    oidcReplaces,
                    (heapAfter - heapBefore) / 1024 / SCOPES,
                    OIDC_SCOPES,
                    requestNanos / 1_000.0);
              });
    }
  }

  /** Median cost of a bearer request to one of the served OIDC scopes. */
  private static long requestCost(final FilterChainProxy proxy, final MockIdentityProvider idp)
      throws Exception {
    final var token = idp.accessToken("svc", "b");
    final List<Long> nanos = new ArrayList<>();
    for (int i = 0; i < 2_000; i++) {
      final var request = new MockHttpServletRequest("GET", oidcScope(i % OIDC_SCOPES) + "/v2/r");
      request.addHeader("Authorization", "Bearer " + token);
      final long start = System.nanoTime();
      final var sent = ScopeRuntimeTestSupport.send(proxy, request);
      nanos.add(System.nanoTime() - start);
      assertThat(sent.status()).isEqualTo(200);
    }
    return nanos.stream().sorted().toList().get(nanos.size() / 2);
  }

  private static Measurement measure(final int count, final IntFunction<ScopeReloadResult> change) {
    final List<ScopeReloadResult> results = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      results.add(change.apply(i));
    }
    return new Measurement(results);
  }

  private static long usedHeap() {
    final Supplier<Long> used =
        () -> Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    System.gc();
    return used.get();
  }

  private static String scope(final int i) {
    return "/scale/basic-" + i;
  }

  private static String oidcScope(final int i) {
    return "/scale/oidc-" + i;
  }

  private record Measurement(List<ScopeReloadResult> results) {

    List<ScopeReloadOutcome> outcomes() {
      return results.stream().map(ScopeReloadResult::outcome).distinct().toList();
    }

    @Override
    public String toString() {
      final var micros =
          results.stream().map(result -> result.duration().toNanos() / 1_000).sorted().toList();
      return "n="
          + micros.size()
          + " p50="
          + micros.get(micros.size() / 2)
          + "us p99="
          + micros.get(micros.size() * 99 / 100)
          + "us max="
          + micros.getLast()
          + "us";
    }
  }
}
