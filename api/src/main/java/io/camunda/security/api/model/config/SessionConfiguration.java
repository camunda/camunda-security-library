/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.time.Duration;

/** Binds {@code camunda.security.session.*} configuration values. */
public class SessionConfiguration {

  public static final String PERSISTENT_ENABLED_PROPERTY =
      "camunda.security.session.persistent.enabled";

  public static final String HEARTBEAT_ENABLED_PROPERTY =
      "camunda.security.session.heartbeat.enabled";

  /** Matches {@code MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS} (30 minutes). */
  private static final Duration DEFAULT_MAX_INACTIVE_INTERVAL = Duration.ofMinutes(30);

  private PersistentConfiguration persistent = new PersistentConfiguration();
  private HeartbeatConfiguration heartbeat = new HeartbeatConfiguration();
  private Duration maxInactiveInterval = DEFAULT_MAX_INACTIVE_INTERVAL;

  public PersistentConfiguration getPersistent() {
    return persistent;
  }

  public void setPersistent(final PersistentConfiguration persistent) {
    this.persistent = persistent;
  }

  public HeartbeatConfiguration getHeartbeat() {
    return heartbeat;
  }

  public void setHeartbeat(final HeartbeatConfiguration heartbeat) {
    this.heartbeat = heartbeat;
  }

  /**
   * How long a session may go without extending activity before it is treated as expired. See
   * ADR-0042. Whether "extending activity" means any request (default) or only a dedicated
   * heartbeat call is controlled independently by {@link #getHeartbeat()}.
   */
  public Duration getMaxInactiveInterval() {
    return maxInactiveInterval;
  }

  public void setMaxInactiveInterval(final Duration maxInactiveInterval) {
    if (maxInactiveInterval == null
        || maxInactiveInterval.isZero()
        || maxInactiveInterval.isNegative()) {
      throw new IllegalArgumentException(
          "camunda.security.session.max-inactive-interval must be a positive duration, but was: "
              + maxInactiveInterval);
    }
    this.maxInactiveInterval = maxInactiveInterval;
  }

  /** Binds {@code camunda.security.session.persistent.*}. */
  public static class PersistentConfiguration {

    private static final boolean DEFAULT_ENABLED = false;

    private boolean enabled = DEFAULT_ENABLED;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }
  }

  /**
   * Binds {@code camunda.security.session.heartbeat.*}. See ADR-0042: when {@code enabled} is
   * {@code false} (the default), every non-polling request extends a session's activity, exactly as
   * before this property existed. When {@code true}, only a call to the dedicated {@code
   * {basePath}/session/heartbeat} endpoint extends it — ordinary application requests stop
   * counting. Hosts should not enable this until their frontend has adopted the corresponding
   * activity-listener package; see the ADR for the rollout sequencing this property exists to
   * support.
   */
  public static class HeartbeatConfiguration {

    private static final boolean DEFAULT_ENABLED = false;

    private boolean enabled = DEFAULT_ENABLED;

    public boolean isEnabled() {
      return enabled;
    }

    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }
  }
}
