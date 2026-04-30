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
 * component. The default library implementation redirects to {@code
 * <contextPath>/<component>/forbidden}. Hosts override this bean to return a 403 JSON body,
 * redirect to a different URL, or any other behaviour.
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
