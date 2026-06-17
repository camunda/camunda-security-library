/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.BasePathSyntax;

/** Shared helpers for scope base-path strings (normalization + validation). */
public final class BasePaths {

  private BasePaths() {}

  /**
   * Validates a scope base path and normalizes it into a URL prefix. Validation is delegated to the
   * shared {@link BasePathSyntax} rule: an absolute, literal path of non-empty segments with no
   * {@code PathPattern} metacharacters (no {@code * ? { }}). The root {@code "/"} maps to the empty
   * prefix (the cluster / non-physical-tenant default); scoped chain builders additionally reject
   * the root. A single trailing slash is stripped.
   *
   * @param path the raw base path
   * @param fieldName field name used in error messages
   * @return the normalized prefix ({@code ""} for the root {@code "/"})
   * @throws IllegalArgumentException if {@code path} is null or not a valid base path
   */
  public static String normalize(final String path, final String fieldName) {
    if ("/".equals(path)) {
      return ""; // root = cluster / non-PT default (BasePaths is lenient here; descriptors reject
      // root)
    }
    BasePathSyntax.requireValid(path, fieldName);
    return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
  }
}
