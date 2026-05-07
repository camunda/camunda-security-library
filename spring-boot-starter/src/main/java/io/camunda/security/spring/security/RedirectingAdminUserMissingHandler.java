/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.spi.AdminUserMissingHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Default {@link AdminUserMissingHandler} reference implementation. Redirects the browser to {@code
 * <contextPath>/admin/setup} so the host's setup UI can render (preserves the legacy OC behaviour).
 *
 * <p>Hosts that prefer a different response shape (forward to a static page, JSON 503, custom
 * telemetry) register their own {@link AdminUserMissingHandler} bean and this default backs off via
 * {@code @ConditionalOnMissingBean}.
 */
public final class RedirectingAdminUserMissingHandler implements AdminUserMissingHandler {

  static final String SETUP_PATH = "/admin/setup";

  @Override
  public void handle(final HttpServletRequest request, final HttpServletResponse response)
      throws IOException {
    response.sendRedirect(request.getContextPath() + SETUP_PATH);
  }
}
