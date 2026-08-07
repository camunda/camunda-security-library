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

  /** Metric description, matching the pre-migration baseline this port restores. */
  String METRIC_DESCRIPTION = "Latency of each authorization check, including cache hits";

  /** Base unit of the recorded duration values. */
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
   * @param durationNanos elapsed time in nanoseconds
   */
  void record(long durationNanos);

  /** No-op implementation used when a host supplies no recorder. */
  static AuthorizationCheckLatencyRecorder noop() {
    return durationNanos -> {};
  }
}
