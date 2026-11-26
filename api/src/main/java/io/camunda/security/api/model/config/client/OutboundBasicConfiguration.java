/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.client;

import org.jspecify.annotations.Nullable;

/**
 * HTTP Basic settings of an outbound client. This class has no {@code toString} method that shows
 * the password.
 */
public final class OutboundBasicConfiguration {

  private @Nullable String username;
  private @Nullable String password;

  public @Nullable String getUsername() {
    return username;
  }

  public void setUsername(final @Nullable String username) {
    this.username = username;
  }

  public @Nullable String getPassword() {
    return password;
  }

  public void setPassword(final @Nullable String password) {
    this.password = password;
  }
}
