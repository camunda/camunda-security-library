/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

/**
 * Immutable configuration for a pre-initialized user.
 *
 * <p>The {@code getX()} methods are provided for backward compatibility with code that was written
 * against the former JavaBean version of this class.
 */
public record ConfiguredUser(String username, String password, String name, String email) {

  /** @deprecated Use {@link #username()} instead. */
  @Deprecated
  public String getUsername() {
    return username;
  }

  /** @deprecated Use {@link #password()} instead. */
  @Deprecated
  public String getPassword() {
    return password;
  }

  /** @deprecated Use {@link #name()} instead. */
  @Deprecated
  public String getName() {
    return name;
  }

  /** @deprecated Use {@link #email()} instead. */
  @Deprecated
  public String getEmail() {
    return email;
  }
}
