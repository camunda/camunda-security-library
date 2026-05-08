/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import java.util.Set;

/**
 * Outbound port the host application implements to declare the HTTP path patterns the security
 * filter chains operate on. The library cannot wire its filter chains without these — APIs,
 * unprotected endpoints, webapp UI paths, and web component identifiers are all host-specific.
 *
 * <p>Path patterns use Spring Security's ant-style syntax ({@code **} for multi-level, {@code *}
 * for single-level).
 */
public interface SecurityPathPort {

  /** Paths that match API endpoints (e.g., {@code "/api/**"}, {@code "/v2/**"}). */
  Set<String> apiPaths();

  /**
   * API paths accessible without authentication (e.g., {@code "/v2/license"}, {@code
   * "/v2/status"}). These must be a subset of {@link #apiPaths()}.
   */
  Set<String> unprotectedApiPaths();

  /**
   * Non-API paths accessible without authentication (e.g., {@code "/actuator/**"}, {@code
   * "/error"}).
   */
  Set<String> unprotectedPaths();

  /** Paths serving web application UI (e.g., {@code "/login/**"}, {@code "/operate/**"}). */
  Set<String> webappPaths();

  /**
   * Web component names for authorization checks — bare path segment identifiers, not ant-style
   * patterns (e.g., {@code "operate"}, {@code "hub"}, not {@code "/operate/**"}).
   */
  Set<String> webComponentNames();

  /**
   * Webapp paths that should be reachable without authentication even on the OIDC webapp chain —
   * typically static UI assets the browser must load before the OAuth2 redirect can be served (e.g.
   * {@code "/default-ui.css"}, {@code "/tasklist/assets/**"}). Default empty.
   */
  default Set<String> unauthenticatedWebappPaths() {
    return Set.of();
  }

  /**
   * Request URI suffixes the web-app authorization filter passes through without invoking a
   * permission check — typically static-asset extensions served by the SPA shell (CSS, JS, images,
   * fonts). Override to add or remove entries; the comparison is plain {@code endsWith} so each
   * entry should include the leading dot (e.g. {@code ".css"}).
   *
   * <p>Default is the set carried over from the OC source ({@code .css}, {@code .js}, {@code
   * .js.map}, {@code .jpg}, {@code .png}, {@code .woff2}, {@code .ico}, {@code .svg}).
   */
  default Set<String> staticResourceSuffixes() {
    return Set.of(".css", ".js", ".js.map", ".jpg", ".png", ".woff2", ".ico", ".svg");
  }

  /**
   * Path prefixes the admin-user setup filter passes through without consulting {@code
   * AdminUserPresencePort} — typically the setup endpoint itself plus any static-assets prefix the
   * setup UI needs to render. Matched against the request's path <em>within the application</em>
   * (i.e. the URI with the servlet context path stripped), so entries remain independent of the
   * deployment's context path. Each entry matches when the path equals the entry exactly or starts
   * with {@code entry + "/"}, so {@code "/admin/setup"} bypasses the setup endpoint without also
   * bypassing {@code "/admin/setupbar"}. These are not Spring Security ant-style patterns. Default
   * empty.
   */
  default Set<String> adminFilterBypassPaths() {
    return Set.of();
  }
}
