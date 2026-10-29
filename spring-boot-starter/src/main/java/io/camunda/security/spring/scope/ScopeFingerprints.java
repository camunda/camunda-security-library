/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Two digests of a scope's {@link AuthenticationConfiguration}, which decide what a change to the
 * scope does.
 *
 * <ul>
 *   <li>{@link #authentication()} covers every property except credentials. A change to it means
 *       the scope authenticates differently — another method, identity provider, client, audience
 *       or claim mapping — so its existing sessions must end. Sessions carry it.
 *   <li>{@link #complete()} covers credentials too. A change to it alone means only a credential
 *       was rotated, and sessions stay.
 * </ul>
 *
 * <p>Both are read from the configuration's bean properties, so a property added to the
 * configuration model later counts as authentication-relevant until it is listed in {@link
 * #CREDENTIAL_PROPERTIES}. Credentials enter {@link #complete()} only as part of a SHA-256 digest
 * and are never kept or logged.
 */
record ScopeFingerprints(String authentication, String complete) {

  /** Property names, at any depth, that hold a credential rather than describe authentication. */
  static final Set<String> CREDENTIAL_PROPERTIES =
      Set.of("clientSecret", "password", "keyPassword", "path", "keyAlias");

  private static final int MAX_DEPTH = 8;
  private static final String MODEL_PACKAGE = "io.camunda.security.api.model.config";

  static ScopeFingerprints of(final AuthenticationConfiguration configuration) {
    final var withoutCredentials = new StringBuilder();
    final var withCredentials = new StringBuilder();
    append(withoutCredentials, configuration, false, 0);
    append(withCredentials, configuration, true, 0);
    return new ScopeFingerprints(sha256(withoutCredentials), sha256(withCredentials));
  }

  /** Whether {@code other} differs from this in credentials only. */
  boolean sameAuthenticationAs(final ScopeFingerprints other) {
    return other != null && authentication.equals(other.authentication);
  }

  boolean sameAs(final ScopeFingerprints other) {
    return other != null && complete.equals(other.complete);
  }

  private static void append(
      final StringBuilder out, final Object value, final boolean credentials, final int depth) {
    if (value == null) {
      out.append("null");
    } else if (depth > MAX_DEPTH) {
      throw new IllegalStateException("Configuration nests deeper than " + MAX_DEPTH + " levels");
    } else if (value instanceof final Map<?, ?> map) {
      appendMap(out, map, credentials, depth);
    } else if (value instanceof final Set<?> set) {
      appendSorted(out, set, credentials, depth);
    } else if (value instanceof final Collection<?> list) {
      out.append('[');
      list.forEach(
          element -> {
            append(out, element, credentials, depth + 1);
            out.append(',');
          });
      out.append(']');
    } else if (value.getClass().getPackageName().startsWith(MODEL_PACKAGE)
        && !value.getClass().isEnum()) {
      appendBean(out, value, credentials, depth);
    } else {
      out.append(value.getClass().getSimpleName()).append(':').append(value);
    }
  }

  private static void appendMap(
      final StringBuilder out, final Map<?, ?> map, final boolean credentials, final int depth) {
    final var sorted = new TreeMap<String, Object>();
    map.forEach((key, entry) -> sorted.put(String.valueOf(key), entry));
    out.append('{');
    sorted.forEach(
        (key, entry) -> {
          out.append(key).append('=');
          append(out, entry, credentials, depth + 1);
          out.append(',');
        });
    out.append('}');
  }

  private static void appendSorted(
      final StringBuilder out, final Set<?> set, final boolean credentials, final int depth) {
    final var elements =
        set.stream()
            .map(
                element -> {
                  final var rendered = new StringBuilder();
                  append(rendered, element, credentials, depth + 1);
                  return rendered.toString();
                })
            .sorted()
            .toList();
    out.append('(').append(String.join(",", elements)).append(')');
  }

  private static void appendBean(
      final StringBuilder out, final Object bean, final boolean credentials, final int depth) {
    out.append(bean.getClass().getSimpleName()).append('{');
    for (final var property : properties(bean.getClass())) {
      if (!credentials && CREDENTIAL_PROPERTIES.contains(property.getName())) {
        continue;
      }
      out.append(property.getName()).append('=');
      append(out, read(bean, property), credentials, depth + 1);
      out.append(';');
    }
    out.append('}');
  }

  private static PropertyDescriptor[] properties(final Class<?> type) {
    try {
      final var properties =
          Introspector.getBeanInfo(type, Object.class).getPropertyDescriptors().clone();
      Arrays.sort(properties, Comparator.comparing(PropertyDescriptor::getName));
      return Arrays.stream(properties)
          .filter(property -> property.getReadMethod() != null)
          .toArray(PropertyDescriptor[]::new);
    } catch (final IntrospectionException e) {
      throw new IllegalStateException("Cannot read the properties of " + type.getName(), e);
    }
  }

  private static Object read(final Object bean, final PropertyDescriptor property) {
    try {
      return property.getReadMethod().invoke(bean);
    } catch (final IllegalAccessException | InvocationTargetException e) {
      throw new IllegalStateException(
          "Cannot read " + bean.getClass().getSimpleName() + "." + property.getName(), e);
    }
  }

  private static String sha256(final CharSequence text) {
    try {
      final var digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of()
          .formatHex(digest.digest(text.toString().getBytes(StandardCharsets.UTF_8)));
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
