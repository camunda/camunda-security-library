/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.regex.Pattern;

/**
 * Shared validator for scope base-path strings.
 *
 * <p>A valid scope base path is absolute, consists of one or more non-empty literal segments (no
 * {@code PathPattern} metacharacters such as {@code * ? { }}), and optionally ends with a single
 * trailing slash. The root {@code "/"} is NOT valid (it has no segment).
 */
public final class BasePathSyntax {

  private static final Pattern VALID = Pattern.compile("^(/[A-Za-z0-9\\-._~%@:+]+)+/?$");

  private BasePathSyntax() {}

  /**
   * Returns {@code true} if {@code path} is a valid scope base path: absolute, one or more
   * non-empty literal segments (no PathPattern metacharacters such as {@code * ? { }}, no
   * empty/double-slash segments), with an optional single trailing slash. The root {@code "/"} is
   * NOT valid (it has no segment).
   */
  public static boolean isValid(final String path) {
    return path != null && VALID.matcher(path).matches();
  }

  /**
   * Returns {@code path} if {@link #isValid} accepts it; otherwise throws.
   *
   * @param path the base path to validate
   * @param fieldName field name used in the error message
   * @return {@code path} unchanged
   * @throws IllegalArgumentException if {@code path} is null or not a valid base path
   */
  public static String requireValid(final String path, final String fieldName) {
    if (!isValid(path)) {
      throw new IllegalArgumentException(
          fieldName
              + " must be an absolute, literal path of non-empty segments (no wildcards or"
              + " PathPattern metacharacters such as * ? { }), e.g. /scope, but was: "
              + path);
    }
    return path;
  }
}
