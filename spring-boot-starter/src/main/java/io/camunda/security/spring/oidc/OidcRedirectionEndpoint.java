/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The path a configured OIDC {@code redirect-uri} mounts its redirection endpoint at.
 *
 * <p>One value decides two things: the {@code redirect_uri} sent to the IdP, and the callback path
 * the webapp chain listens on. Deriving the second from the first lives here because both the chain
 * that mounts the endpoint and the validation that rejects a value the chain cannot mount have to
 * agree on it, and neither of them owns the rule.
 */
public final class OidcRedirectionEndpoint {

  /** The callback path served when no {@code redirect-uri} is configured. */
  public static final String DEFAULT_PATH = "/sso-callback";

  private static final String BASE_URL_PLACEHOLDER = "{baseUrl}";
  private static final String BASE_PATH_PLACEHOLDER = "{basePath}";
  private static final Logger LOG = LoggerFactory.getLogger(OidcRedirectionEndpoint.class);

  private OidcRedirectionEndpoint() {}

  /**
   * Resolves the redirection-endpoint path from a configured {@code redirect-uri}, relative to the
   * servlet {@code contextPath}, falling back to {@code defaultPath} when the value is unset or
   * carries no callback path of its own.
   *
   * <p>The context path is taken off only a value that spells it out, as the absolute URL the chart
   * renders for a context-path'd webapp does. One carrying it through {@code {baseUrl}} or {@code
   * {basePath}} has it accounted for already, since the resolver expands both from {@code
   * request.getContextPath()}.
   *
   * <p>A {@code {registrationId}} placeholder is rewritten to a {@code *} wildcard so the matcher
   * states the intent — any registration id — rather than relying on {@code
   * PathPatternRequestMatcher} reading the left-over placeholder as a single-segment path variable.
   *
   * @throws IllegalArgumentException if the value yields a non-blank path not starting with {@code
   *     "/"} (e.g. {@code "{baseUrl}api/callback"}), which {@code
   *     redirectionEndpoint().baseUri(...)} requires
   */
  public static String resolve(
      final String configuredRedirectUri, final String contextPath, final String defaultPath) {
    if (configuredRedirectUri == null || configuredRedirectUri.isBlank()) {
      return defaultPath;
    }
    String path = configuredRedirectUri.trim();
    boolean contextPathCarriedByAPlaceholder = false;
    if (path.startsWith(BASE_URL_PLACEHOLDER)) {
      path = path.substring(BASE_URL_PLACEHOLDER.length());
      contextPathCarriedByAPlaceholder = true;
    } else {
      final int scheme = path.indexOf("://");
      if (scheme >= 0) {
        final int slash = path.indexOf('/', scheme + 3);
        final String beforeThePath = slash >= 0 ? path.substring(0, slash) : path;
        contextPathCarriedByAPlaceholder = beforeThePath.contains(BASE_PATH_PLACEHOLDER);
        path = slash >= 0 ? path.substring(slash) : "";
      }
    }
    final int query = path.indexOf('?');
    if (query >= 0) {
      path = path.substring(0, query);
    }
    final int fragment = path.indexOf('#');
    if (fragment >= 0) {
      path = path.substring(0, fragment);
    }
    if (!contextPathCarriedByAPlaceholder) {
      path = stripContextPath(path, contextPath);
    }
    // Spring's default template ends in "{registrationId}"; the redirection-endpoint matcher must
    // use an Ant wildcard for that segment so it matches the resolved id (e.g. ".../code/oidc").
    path = path.replace("{registrationId}", "*");
    if (path.isBlank()) {
      LOG.warn(
          "OIDC redirect-uri '{}' carries no callback path beyond the servlet context-path '{}'; "
              + "falling back to the default redirection-endpoint path '{}'. The OIDC login "
              + "callback will be served at that default — set a redirect-uri with an explicit "
              + "callback segment to override it.",
          configuredRedirectUri,
          contextPath,
          defaultPath);
      return defaultPath;
    }
    if (!path.startsWith("/")) {
      throw new IllegalArgumentException(
          "OIDC redirect-uri must resolve to a path starting with '/', but '"
              + configuredRedirectUri
              + "' resolved to: "
              + path);
    }
    // Log the resolved matcher path so the callback the chain listens on is reconstructable from
    // logs alone (this resolution silently broke logins for a full alpha cycle — see GH-569).
    LOG.debug(
        "Resolved OIDC redirection-endpoint path '{}' from redirect-uri '{}' (servlet context-path"
            + " '{}')",
        path,
        configuredRedirectUri,
        contextPath);
    return path;
  }

  /**
   * Removes a leading servlet {@code contextPath} segment from an application-relative {@code
   * path}, matching whole segments only, so {@code /orchestration} does not strip the prefix of
   * {@code /orchestration-ui/...}. Returns {@code path} unchanged when {@code contextPath} is blank
   * or the root {@code "/"}, and {@code ""} when {@code path} is the context-path itself.
   */
  public static String stripContextPath(final String path, final String contextPath) {
    if (contextPath == null || contextPath.isBlank() || "/".equals(contextPath)) {
      return path;
    }
    final String normalized =
        contextPath.endsWith("/")
            ? contextPath.substring(0, contextPath.length() - 1)
            : contextPath;
    final String withTrailingSlash = normalized + "/";
    if (path.equals(normalized) || path.equals(withTrailingSlash)) {
      return "";
    }
    if (path.startsWith(withTrailingSlash)) {
      return path.substring(normalized.length());
    }
    return path;
  }
}
