/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import io.camunda.security.api.model.CamundaAuthentication;

/**
 * Converts framework-specific authentication representations into {@link CamundaAuthentication}.
 *
 * @param <T> the authentication source type supported by this converter
 */
public interface CamundaAuthenticationConverter<T> {

  /**
   * Checks whether this converter can handle the given authentication object.
   *
   * @param authentication the authentication object to evaluate
   * @return {@code true} when this converter supports the given authentication, otherwise {@code
   *     false}
   */
  boolean supports(final T authentication);

  /**
   * Converts the given authentication object into a {@link CamundaAuthentication}.
   *
   * @param authentication the authentication object to convert
   * @return the converted {@link CamundaAuthentication}
   */
  CamundaAuthentication convert(final T authentication);
}
