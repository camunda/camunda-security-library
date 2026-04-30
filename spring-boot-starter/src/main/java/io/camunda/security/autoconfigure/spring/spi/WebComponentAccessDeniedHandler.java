/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.spi;

import io.camunda.security.core.authorization.CamundaAuthentication;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Decides what to do when the {@code WebComponentAuthorizationCheckFilter} denies access to a
 * component. Hosts implement this SPI to return a 403 JSON body, redirect to a URL, or apply any
 * other access-denied behaviour appropriate for the host.
 */
@FunctionalInterface
public interface WebComponentAccessDeniedHandler {

  void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      String component,
      CamundaAuthentication authentication)
      throws IOException;
}
