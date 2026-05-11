/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.spring.spi.WebAppAccessDeniedHandlerPort;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Default {@link WebAppAccessDeniedHandlerPort} reference implementation. Redirects the browser to
 * {@code <contextPath>/<webApp>/forbidden} so the host's webapp shell can render its own forbidden
 * page (preserves the legacy OC behaviour).
 *
 * <p>Hosts that prefer a different response shape (e.g. a 403 JSON body, a forward to a static
 * error page) register their own bean and this default backs off via
 * {@code @ConditionalOnMissingBean}.
 */
public final class RedirectingWebAppAccessDeniedAdapter implements WebAppAccessDeniedHandlerPort {

  @Override
  public void handle(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final String webApp,
      final CamundaAuthentication authentication)
      throws IOException {
    response.sendRedirect(request.getContextPath() + "/" + webApp + "/forbidden");
  }
}
