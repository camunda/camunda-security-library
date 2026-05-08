/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.filter;

import jakarta.servlet.http.HttpServletRequest;

/** Static helpers for working with HTTP request paths inside CSL filters. */
public final class RequestPathSupport {

  private RequestPathSupport() {
    // static-only
  }

  /**
   * Returns the path within the application — i.e. the request URI with the deployment's servlet
   * context path stripped off. Composes {@link HttpServletRequest#getServletPath()} and {@link
   * HttpServletRequest#getPathInfo()}, mirroring the convention Spring Security uses internally.
   *
   * <p>Use this when matching a request against host-supplied path patterns that must remain
   * independent of the deployment's context path — otherwise, an app deployed under {@code
   * /operate} would never match a host-configured pattern like {@code /admin/setup}.
   */
  public static String pathWithinApplication(final HttpServletRequest request) {
    final String servletPath = request.getServletPath();
    final String pathInfo = request.getPathInfo();
    if (servletPath == null) {
      return pathInfo == null ? "" : pathInfo;
    }
    return pathInfo == null ? servletPath : servletPath + pathInfo;
  }
}
