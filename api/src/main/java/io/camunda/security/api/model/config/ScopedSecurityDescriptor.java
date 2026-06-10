/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.Objects;

/** A path-scoped security chain request: base path + the merged auth config for that scope. */
public record ScopedSecurityDescriptor(
    String basePath, AuthenticationConfiguration authentication) {

  public ScopedSecurityDescriptor {
    if (basePath == null || basePath.isBlank()) {
      throw new IllegalArgumentException("ScopedSecurityDescriptor basePath must be non-blank");
    }
    if (!basePath.startsWith("/") || "/".equals(basePath)) {
      throw new IllegalArgumentException(
          "ScopedSecurityDescriptor basePath must be a non-root absolute path starting with '/'"
              + " (e.g. /my-scope); got: "
              + basePath);
    }
    if (basePath.indexOf('*') >= 0 || basePath.indexOf('?') >= 0) {
      throw new IllegalArgumentException(
          "ScopedSecurityDescriptor basePath must be a literal path prefix, not an ant-style"
              + " pattern (no '*' or '?'); got: "
              + basePath);
    }
    Objects.requireNonNull(
        authentication, "ScopedSecurityDescriptor authentication must not be null");
  }
}
