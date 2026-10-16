/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Helpers for the neutral attribute tree (nested maps and lists). */
public final class ScimTrees {

  private ScimTrees() {}

  /** Deep, mutable copy of a tree. */
  @SuppressWarnings("unchecked")
  public static Map<String, Object> deepCopy(final Map<String, Object> source) {
    final Map<String, Object> copy = new LinkedHashMap<>();
    source.forEach((k, v) -> copy.put(k, copyValue(v)));
    return copy;
  }

  @SuppressWarnings("unchecked")
  public static Object copyValue(final Object value) {
    if (value instanceof Map<?, ?> m) {
      return deepCopy((Map<String, Object>) m);
    }
    if (value instanceof List<?> l) {
      final List<Object> copy = new ArrayList<>();
      l.forEach(e -> copy.add(copyValue(e)));
      return copy;
    }
    return value;
  }

  /** Finds the existing key of {@code map} matching {@code name} case-insensitively. */
  public static String findKey(final Map<String, Object> map, final String name) {
    final String wanted = name.toLowerCase(Locale.ROOT);
    for (final String key : map.keySet()) {
      if (key.toLowerCase(Locale.ROOT).equals(wanted)) {
        return key;
      }
    }
    return null;
  }
}
