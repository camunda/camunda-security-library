/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link RequestMatcher} that decides whether a request requires CSRF protection. Safe HTTP methods
 * (GET, HEAD, TRACE, OPTIONS) are always excluded, as are configured allowed paths and requests
 * originating from the Swagger UI.
 *
 * <p>Allowed paths are matched via Spring Security's {@link PathPatternRequestMatcher} (the default
 * in Spring Security 7) rather than a hand-rolled regex, so ant-style patterns ({@code /v1/**},
 * {@code /login}) are interpreted by the same engine that matches them everywhere else in the
 * security configuration.
 */
public final class CsrfProtectionRequestMatcher implements RequestMatcher {

  private static final Logger LOG = LoggerFactory.getLogger(CsrfProtectionRequestMatcher.class);

  private static final Pattern ALLOWED_METHODS = Pattern.compile("^(GET|HEAD|TRACE|OPTIONS)$");

  private static final RequestMatcher NEVER_MATCHES = request -> false;

  private final RequestMatcher allowedPathsMatcher;

  public CsrfProtectionRequestMatcher(final Set<String> allowedPaths) {
    this.allowedPathsMatcher = buildAllowedPathsMatcher(allowedPaths);
    LOG.debug("CSRF protection configuration - allowed paths: {}", allowedPaths);
  }

  @Override
  public boolean matches(final HttpServletRequest request) {
    if (ALLOWED_METHODS.matcher(request.getMethod()).matches()) {
      return false;
    }

    if (allowedPathsMatcher.matches(request)) {
      return false;
    }

    if (isSwaggerUiReferer(request)) {
      return false;
    }

    return request.getSession(false) != null;
  }

  private static RequestMatcher buildAllowedPathsMatcher(final Set<String> paths) {
    if (paths == null || paths.isEmpty()) {
      return NEVER_MATCHES;
    }
    final List<RequestMatcher> matchers =
        paths.stream()
            .map(path -> (RequestMatcher) PathPatternRequestMatcher.withDefaults().matcher(path))
            .toList();
    return matchers.size() == 1 ? matchers.get(0) : new OrRequestMatcher(matchers);
  }

  private static boolean isSwaggerUiReferer(final HttpServletRequest request) {
    final String referer = request.getHeader(HttpHeaders.REFERER);
    if (referer == null) {
      return false;
    }
    final URL requestUrl;
    try {
      requestUrl = URI.create(request.getRequestURL().toString()).toURL();
    } catch (final MalformedURLException e) {
      throw new IllegalArgumentException("Cannot parse request URL", e);
    }
    final String basePrefix =
        requestUrl.getProtocol()
            + "://"
            + requestUrl.getHost()
            + (requestUrl.getPort() > 0 ? ":" + requestUrl.getPort() : "");
    return referer.startsWith(basePrefix) && referer.contains("/swagger-ui");
  }
}
