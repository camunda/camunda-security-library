/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.core.auth.RequiredAuthorization;
import java.util.Objects;

public record ResourceAccess(
    boolean allowed, boolean wildcard, RequiredAuthorization<?> authorization) {

  public ResourceAccess {
    Objects.requireNonNull(authorization, "Authorization must not be null");
  }

  public boolean denied() {
    return !allowed;
  }

  public static ResourceAccess allowed(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, false, authorization);
  }

  public static ResourceAccess denied(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(false, false, authorization);
  }

  public static ResourceAccess wildcard(final RequiredAuthorization<?> authorization) {
    return new ResourceAccess(true, true, authorization);
  }
}
