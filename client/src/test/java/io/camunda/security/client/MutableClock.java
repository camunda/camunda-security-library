/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** Clock the test advances by hand. */
final class MutableClock extends Clock {

  private volatile Instant now = Instant.parse("2026-01-01T00:00:00Z");

  void advance(final Duration duration) {
    now = now.plus(duration);
  }

  @Override
  public ZoneId getZone() {
    return ZoneOffset.UTC;
  }

  @Override
  public Clock withZone(final ZoneId zone) {
    return this;
  }

  @Override
  public Instant instant() {
    return now;
  }
}
