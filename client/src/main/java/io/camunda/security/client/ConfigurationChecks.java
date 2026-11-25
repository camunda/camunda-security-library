/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** All argument checks of the configuration classes. */
final class ConfigurationChecks {

  // Upper limit for all timeouts. The HTTP connection takes an int of milliseconds.
  static final Duration MAX_TIMEOUT = Duration.ofMillis(Integer.MAX_VALUE);
  private static final List<String> LOOPBACK_HOSTS =
      Collections.unmodifiableList(Arrays.asList("localhost", "127.0.0.1", "[::1]"));

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

  /** The value, or {@code null} if the value is blank. */
  static String nullIfBlank(final String value) {
    return isBlank(value) ? null : value;
  }

  static void requireNoColon(final String value, final String name) {
    if (value.contains(":")) {
      throw new IllegalArgumentException(name + " must not contain ':'");
    }
  }

  /**
   * An absolute {@code https} URI with a host and without user-info. {@code http} sends the secret
   * in clear text, so it is allowed only for a loopback host. {@link URI#getHost()} keeps the
   * brackets of an IPv6 address. {@code java.net.URI} reads no host name that has an underscore.
   */
  static void requireTokenUri(final URI uri, final String name) {
    if (uri == null || !isHttpScheme(uri.getScheme())) {
      throw new IllegalArgumentException(name + " must be an absolute http or https URI");
    }
    if (uri.getHost() == null) {
      throw new IllegalArgumentException(name + " has no host that java.net.URI can read");
    }
    if (uri.getRawUserInfo() != null) {
      throw new IllegalArgumentException(name + " must not contain user-info");
    }
    if ("http".equalsIgnoreCase(uri.getScheme()) && !isLoopbackHost(uri.getHost())) {
      throw new IllegalArgumentException(
          name + " must use https. Http is allowed only for localhost, 127.0.0.1 and [::1]");
    }
  }

  private static boolean isHttpScheme(final String scheme) {
    return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
  }

  private static boolean isLoopbackHost(final String host) {
    return LOOPBACK_HOSTS.stream().anyMatch(host::equalsIgnoreCase);
  }

  /** An unmodifiable copy. {@code null} gives an empty list. A value must not be blank. */
  static List<String> copyNonBlank(final List<String> values, final String name) {
    if (values == null) {
      return Collections.emptyList();
    }
    for (final String value : values) {
      if (isBlank(value)) {
        throw new IllegalArgumentException(name + " must not contain blank values");
      }
    }
    return Collections.unmodifiableList(new ArrayList<>(values));
  }

  /** {@code null} gives the default. Otherwise positive and at most {@link #MAX_TIMEOUT}. */
  static Duration positiveOrDefault(
      final Duration value, final Duration defaultValue, final String name) {
    if (value == null) {
      return defaultValue;
    }
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    if (value.compareTo(MAX_TIMEOUT) > 0) {
      throw new IllegalArgumentException(
          name + " must not be longer than " + Integer.MAX_VALUE + " milliseconds");
    }
    return value;
  }
}
