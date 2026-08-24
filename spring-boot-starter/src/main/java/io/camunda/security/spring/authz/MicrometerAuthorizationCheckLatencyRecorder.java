/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.authz;

import io.camunda.security.core.port.out.AuthorizationCheckLatencyRecorder;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Micrometer-backed {@link AuthorizationCheckLatencyRecorder}. Builds its {@link Timer} from the
 * port's name, description, and SLO-bucket constants, so this adapter and any other host's adapter
 * (e.g. zeebe/engine's non-Spring recorder) publish the same metric definition for those fields.
 * {@code METRIC_BASE_UNIT} is excepted — {@code Timer.Builder} has no {@code baseUnit(...)} setter,
 * so this adapter's meter does not carry it. See ADR-0041.
 */
final class MicrometerAuthorizationCheckLatencyRecorder
    implements AuthorizationCheckLatencyRecorder {

  private final Timer timer; // nullable — metrics are optional

  MicrometerAuthorizationCheckLatencyRecorder(final MeterRegistry meterRegistry) {
    timer =
        meterRegistry == null
            ? null
            : Timer.builder(METRIC_NAME)
                .description(METRIC_DESCRIPTION)
                .serviceLevelObjectives(METRIC_SLO_BUCKETS.toArray(new Duration[0]))
                .register(meterRegistry);
  }

  @Override
  public void record(final long durationNanos) {
    if (timer == null) {
      return;
    }
    timer.record(durationNanos, TimeUnit.NANOSECONDS);
  }
}
