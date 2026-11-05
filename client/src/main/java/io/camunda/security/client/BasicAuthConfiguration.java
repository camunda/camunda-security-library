/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.util.Objects;

/** Username and password for HTTP Basic authentication. */
public final class BasicAuthConfiguration {

  private final String username;
  private final String password;

  /**
   * @param username the user name; it must not be blank and must not contain {@code ':'}
   * @param password the password; it must not be null
   */
  public BasicAuthConfiguration(final String username, final String password) {
    ConfigurationChecks.requireText(username, "username");
    if (username.contains(":")) {
      throw new IllegalArgumentException("username must not contain ':'");
    }
    Objects.requireNonNull(password, "password must not be null");
    this.username = username;
    this.password = password;
  }

  public String username() {
    return username;
  }

  public String password() {
    return password;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof BasicAuthConfiguration)) {
      return false;
    }
    final BasicAuthConfiguration other = (BasicAuthConfiguration) o;
    return username.equals(other.username) && password.equals(other.password);
  }

  @Override
  public int hashCode() {
    return Objects.hash(username, password);
  }

  @Override
  public String toString() {
    return "BasicAuthConfiguration[username=" + username + ", password=***]";
  }
}
