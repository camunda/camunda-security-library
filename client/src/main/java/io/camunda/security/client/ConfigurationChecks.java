/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

/** Argument checks shared by the configuration classes. */
final class ConfigurationChecks {

  private ConfigurationChecks() {}

  static void requireText(final String value, final String name) {
    if (isBlank(value)) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }

  /** True if the value is null, empty or only whitespace. Java 8 has no {@code String.isBlank}. */
  static boolean isBlank(final String value) {
    if (value == null) {
      return true;
    }
    return value.codePoints().allMatch(Character::isWhitespace);
  }
}
