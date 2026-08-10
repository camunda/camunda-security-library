/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import java.time.Duration;
import java.util.List;

/**
 * Outbound port for recording the latency of a single authorization check. {@code core} carries no
 * Micrometer dependency, so this port takes a plain elapsed duration and each host wires its own
 * meter-backed implementation (see {@code spring-boot-starter}'s Spring adapter and zeebe/engine's
 * non-Spring adapter) against the shared spec constants declared here, so both hosts publish the
 * exact same metric definition. See ADR-0041.
 *
 * <p>{@link io.camunda.security.core.authz.AuthorizationService} times only its two terminal {@code
 * check(...)} overloads (scope-based and property-based); the claims-map overload is a pure
 * delegation to the scope-based overload and is intentionally left untimed to avoid double-counting
 * a single logical check as two samples.
 */
public interface AuthorizationCheckLatencyRecorder {

  /** Metric name, matching the pre-migration baseline this port restores. */
  String METRIC_NAME = "zeebe.authorization.check.latency";

  /**
   * Metric description. Deviates from the pre-migration baseline text by dropping "including cache
   * hits" — {@link io.camunda.security.core.authz.AuthorizationService}'s timed overloads have no
   * cache in their timed region; the re-homed cache-access metrics live outside this window. See
   * ADR-0041.
   */
  String METRIC_DESCRIPTION = "Latency of each authorization check";

  /**
   * Base unit of the recorded duration values. Declares the unit convention {@link #record(long)}
   * uses; not applied to the {@code spring-boot-starter} adapter's Micrometer {@code Timer}, which
   * has no {@code baseUnit(...)} setter (unlike {@code Gauge}/{@code Counter}/{@code
   * DistributionSummary}) — a Timer's reported unit is registry-defined instead. The deleted
   * pre-migration baseline had the same gap. See ADR-0041's Amendments.
   */
  String METRIC_BASE_UNIT = "ns";

  /** SLO histogram buckets, matching the pre-migration baseline this port restores. */
  List<Duration> METRIC_SLO_BUCKETS =
      List.of(
          Duration.ofNanos(100_000),
          Duration.ofNanos(500_000),
          Duration.ofMillis(1),
          Duration.ofMillis(5),
          Duration.ofMillis(10),
          Duration.ofMillis(50),
          Duration.ofMillis(100),
          Duration.ofMillis(500));

  /**
   * Records the elapsed wall-clock time of one authorization check, including any short-circuit
   * taken before the check logic runs.
   *
   * <p>{@link io.camunda.security.core.authz.AuthorizationService} calls this from a {@code
   * finally} block and guards against a {@link RuntimeException} escaping it, so a failing
   * implementation can never affect an authorization decision. Implementations are not required to
   * guard themselves, but should not rely on the caller's guard as a substitute for handling
   * expected failure modes internally.
   *
   * @param durationNanos elapsed time in nanoseconds
   */
  void record(long durationNanos);

  /** No-op implementation used when a host supplies no recorder. */
  static AuthorizationCheckLatencyRecorder noop() {
    return durationNanos -> {};
  }
}
