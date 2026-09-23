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
   * <p>A value that resolves to a path without a leading slash — {@code
   * redirectionEndpoint().baseUri(...)} needs one — falls back to {@code defaultPath} with a {@code
   * WARN}, the same as a value with no callback path at all.
   */
  public static String resolve(
      final String configuredRedirectUri, final String contextPath, final String defaultPath) {
    if (configuredRedirectUri == null || configuredRedirectUri.isBlank()) {
      return defaultPath;
    }
    final var template = pathOfTheTemplate(configuredRedirectUri.trim());
    var path = withoutQueryAndFragment(template.path());
    if (!template.contextPathCarriedByAPlaceholder()) {
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
          UrlRedaction.redact(configuredRedirectUri),
          contextPath,
          defaultPath);
      return defaultPath;
    }
    if (!path.startsWith("/")) {
      LOG.warn(
          "OIDC redirect-uri '{}' resolves to a path that does not start with '/' (was: '{}');"
              + " falling back to the default redirection-endpoint path '{}'. The OIDC login"
              + " callback will be served at that default instead.",
          UrlRedaction.redact(configuredRedirectUri),
          UrlRedaction.redact(path),
          defaultPath);
      return defaultPath;
    }
    // Log the resolved matcher path so the callback the chain listens on is reconstructable from
    // logs alone (this resolution silently broke logins for a full alpha cycle — see GH-569).
    LOG.debug(
        "Resolved OIDC redirection-endpoint path '{}' from redirect-uri '{}' (servlet context-path"
            + " '{}')",
        UrlRedaction.redact(path),
        UrlRedaction.redact(configuredRedirectUri),
        contextPath);
    return path;
  }

  /**
   * Takes the path off a template, whether the template starts with {@code {baseUrl}} or spells the
   * scheme and authority out. A template with neither is a path already.
   */
  private static TemplatePath pathOfTheTemplate(final String template) {
    if (template.startsWith(BASE_URL_PLACEHOLDER)) {
      return new TemplatePath(template.substring(BASE_URL_PLACEHOLDER.length()), true);
    }
    final int scheme = template.indexOf("://");
    if (scheme < 0) {
      return new TemplatePath(template, false);
    }
    final int slash = template.indexOf('/', scheme + 3);
    final String beforeThePath = slash >= 0 ? template.substring(0, slash) : template;
    return new TemplatePath(
        slash >= 0 ? template.substring(slash) : "", beforeThePath.contains(BASE_PATH_PLACEHOLDER));
  }

  /**
   * The matcher sees the request path only, so a query the IdP is told about and a fragment do not
   * belong in the endpoint pattern.
   */
  private static String withoutQueryAndFragment(final String path) {
    final int end = Math.min(indexOrEnd(path, '?'), indexOrEnd(path, '#'));
    return path.substring(0, end);
  }

  private static int indexOrEnd(final String path, final char delimiter) {
    final int index = path.indexOf(delimiter);
    return index >= 0 ? index : path.length();
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

  /**
   * The path part of a redirect-uri template, and whether a placeholder in front of it expands to
   * the context path. The two travel together because the second answer decides whether {@link
   * #stripContextPath} may touch the first.
   */
  private record TemplatePath(String path, boolean contextPathCarriedByAPlaceholder) {}
}
