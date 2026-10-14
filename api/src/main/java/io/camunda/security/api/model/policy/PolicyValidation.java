/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import java.util.List;
import java.util.Set;

/** Shared validation and normalisation helpers for the policy change-set records. */
final class PolicyValidation {

  private PolicyValidation() {}

  static String requireId(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be null or blank");
    }
    return value;
  }

  static List<String> requireIds(final List<String> ids, final String field) {
    ids.forEach(id -> requireId(id, field));
    return ids;
  }

  static <T> List<T> listOrEmpty(final List<T> list) {
    return list == null ? List.of() : List.copyOf(list);
  }

  static <T> Set<T> setOrEmpty(final Set<T> set) {
    return set == null ? Set.of() : Set.copyOf(set);
  }

  static String nullToEmpty(final String value) {
    return value == null ? "" : value;
  }
}
