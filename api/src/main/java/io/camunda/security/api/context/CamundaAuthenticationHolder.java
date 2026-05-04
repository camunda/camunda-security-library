/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.CamundaAuthentication;

/** Associates a given {@link CamundaAuthentication} with the current request handling context. */
public interface CamundaAuthenticationHolder {

  /**
   * Returns true if this holder can store a {@link CamundaAuthentication} for the current execution
   * context.
   */
  boolean supports();

  /**
   * Associates a given {@link CamundaAuthentication} with the current thread of execution while
   * processing the request.
   */
  void set(final CamundaAuthentication authentication);

  /** Obtains the current {@link CamundaAuthentication}, or null if not present. */
  CamundaAuthentication get();
}
