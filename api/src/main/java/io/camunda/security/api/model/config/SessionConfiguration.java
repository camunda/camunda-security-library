/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

/** Binds {@code camunda.security.session.*} configuration values. */
public class SessionConfiguration {

  public static final String PERSISTENT_ENABLED_PROPERTY =
      "camunda.security.session.persistent.enabled";

  private PersistentConfiguration persistent = new PersistentConfiguration();

  public PersistentConfiguration getPersistent() {
    return persistent;
  }

  public void setPersistent(final PersistentConfiguration persistent) {
    this.persistent = persistent;
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
}
