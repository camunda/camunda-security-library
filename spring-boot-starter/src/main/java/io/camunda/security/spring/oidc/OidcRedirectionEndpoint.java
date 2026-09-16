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
 * The path where a configured OIDC {@code redirect-uri} mounts its redirection endpoint.
 *
 * <p>One value decides two things. It is the {@code redirect_uri} that the application sends to the
 * IdP, and it gives the callback path where the webapp chain listens. This class holds the rule
 * that derives the second value from the first value. Two components need that rule: the chain that
 * mounts the endpoint, and the validation that rejects a value the chain cannot mount. Neither
 * component owns the rule, and both must apply it in the same way.
 */
public final class OidcRedirectionEndpoint {

  /** The callback path that the application serves if you configure no {@code redirect-uri}. */
  public static final String DEFAULT_PATH = "/sso-callback";

  private static final String BASE_URL_PLACEHOLDER = "{baseUrl}";
  private static final String BASE_PATH_PLACEHOLDER = "{basePath}";
  private static final Logger LOG = LoggerFactory.getLogger(OidcRedirectionEndpoint.class);

  private OidcRedirectionEndpoint() {}

  /**
   * Resolves the redirection-endpoint path from a configured {@code redirect-uri}. The result is
   * relative to the servlet {@code contextPath}. If the value has no callback path of its own, the
   * method returns {@code defaultPath}.
   *
   * <p>The method removes the context path only from a value that contains it, as the absolute URL
   * for a webapp with a context path does. A value that carries the context path in {@code
   * {baseUrl}} or {@code {basePath}} accounts for it already, because the resolver expands both
   * placeholders from {@code request.getContextPath()}.
   *
   * <p>The method replaces a {@code {registrationId}} placeholder with a {@code *} wildcard. The
   * wildcard makes the intention clear: the matcher accepts any registration id. Without the
   * wildcard, the result depends on {@code PathPatternRequestMatcher}, which reads the remaining
   * placeholder as a path variable for one segment.
   *
   * @throws IllegalArgumentException if the value gives a path that is not blank and does not start
   *     with {@code "/"}, because {@code redirectionEndpoint().baseUri(...)} needs a leading slash
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
   * Removes a leading servlet {@code contextPath} from an application-relative {@code path}. The
   * method compares complete segments only. A {@code /context} context path therefore does not
   * shorten a callback at {@code /contextual/sso-callback}. If the path is the context path itself,
   * the method returns {@code ""}. The caller then decides what a value without a callback segment
   * means.
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
