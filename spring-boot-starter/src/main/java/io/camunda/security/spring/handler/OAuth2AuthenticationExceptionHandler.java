/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import static io.camunda.security.spring.oidc.ScopedClientRegistrationFactory.sanitizeForLog;

import io.camunda.security.spring.spi.OidcLoginFailureNotice;
import io.camunda.security.spring.spi.OidcLoginFailurePort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.util.HtmlUtils;

/**
 * Handles OIDC login failures on the stateful webapp chains.
 *
 * <ul>
 *   <li>The {@code authorization_request_not_found} OAuth2 error redirects to the application root,
 *       so the user can restart the login flow.
 *   <li>Any other failure of a browser request renders a small HTML page that says the login failed
 *       and links back to the application, instead of a bare error response. The text comes from
 *       the host's {@link OidcLoginFailurePort} when it has something to say, otherwise it is
 *       generic. The page never repeats the exception message: an ID-token validation failure
 *       quotes the token's claims in it.
 *   <li>Any other failure of a non-browser request is delegated to the wrapped failure handler
 *       (default {@link SimpleUrlAuthenticationFailureHandler}, which sends a 401).
 * </ul>
 *
 * <p>The page links back to the application rather than redirecting there: with an IdP that keeps
 * its own session, an automatic redirect would sign the user straight back in and fail again, in a
 * loop.
 *
 * <p>The redirect goes through {@link DefaultRedirectStrategy} rather than {@link
 * HttpServletResponse#sendRedirect(String)}, because the latter would send the user to the host
 * root: it does not prepend the servlet context path, so a webapp served under one (for example
 * {@code /<clusterId>} on CCSaaS) would recover to a location outside the application. See ADR-0036
 * for the failed-login page.
 */
public final class OAuth2AuthenticationExceptionHandler implements AuthenticationFailureHandler {

  public static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE =
      "authorization_request_not_found";

  static final String GENERIC_TITLE = "Sign-in failed";
  static final String GENERIC_MESSAGE =
      "We could not sign you in to this application. Your account may not have access to it."
          + " Try again, or contact your administrator if the problem continues.";
  static final String TRY_AGAIN = "Try again";

  private static final Logger LOG =
      LoggerFactory.getLogger(OAuth2AuthenticationExceptionHandler.class);
  private static final MediaTypeRequestMatcher BROWSER_REQUEST = browserRequestMatcher();

  private final AuthenticationFailureHandler delegate;
  private final OidcLoginFailurePort loginFailurePort;
  private final String applicationRoot;
  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  public OAuth2AuthenticationExceptionHandler() {
    this(new SimpleUrlAuthenticationFailureHandler());
  }

  public OAuth2AuthenticationExceptionHandler(final AuthenticationFailureHandler delegate) {
    this(delegate, null, "/");
  }

  /**
   * @param delegate handles failures of non-browser requests
   * @param loginFailurePort the host's explanations, or {@code null} for the generic page only
   * @param applicationRoot the path the page links back to, relative to the servlet context, such
   *     as {@code /} or a scoped chain's {@code /<basePath>/}
   */
  public OAuth2AuthenticationExceptionHandler(
      final AuthenticationFailureHandler delegate,
      final OidcLoginFailurePort loginFailurePort,
      final String applicationRoot) {
    this.delegate = delegate;
    this.loginFailurePort = loginFailurePort;
    this.applicationRoot = applicationRoot;
  }

  @Override
  public void onAuthenticationFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException exception)
      throws IOException, ServletException {

    if (isAuthorizationRequestNotFound(exception)) {
      redirectStrategy.sendRedirect(request, response, "/");
      return;
    }

    logFailure(request, exception);
    if (!BROWSER_REQUEST.matches(request) || response.isCommitted()) {
      delegate.onAuthenticationFailure(request, response, exception);
      return;
    }
    renderPage(request, response, noticeFor(request, exception));
  }

  private OidcLoginFailureNotice noticeFor(
      final HttpServletRequest request, final AuthenticationException exception) {
    if (loginFailurePort != null) {
      try {
        final Optional<OidcLoginFailureNotice> notice =
            loginFailurePort.explain(request, exception);
        if (notice != null && notice.isPresent()) {
          return notice.get();
        }
      } catch (final RuntimeException e) {
        // Type only: the port inspects the same exception whose message quotes token claims.
        LOG.warn(
            "OidcLoginFailurePort failed with {} while explaining a failed OIDC login; showing the"
                + " generic failed-login page instead.",
            e.getClass().getName());
      }
    }
    return new OidcLoginFailureNotice(401, GENERIC_TITLE, GENERIC_MESSAGE);
  }

  private void renderPage(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final OidcLoginFailureNotice notice)
      throws IOException {
    final String retryTarget = request.getContextPath() + applicationRoot;
    final String forwardLink =
        notice
            .optionalLink()
            .map(link -> anchor(link.target().toString(), link.text()) + " ")
            .orElse("");
    final String page =
        """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>%1$s</title>
        </head>
        <body>
        <main>
        <h1>%1$s</h1>
        <p>%2$s</p>
        <p>%3$s%4$s</p>
        </main>
        </body>
        </html>
        """
            .formatted(
                HtmlUtils.htmlEscape(notice.title()),
                HtmlUtils.htmlEscape(notice.message()),
                forwardLink,
                anchor(retryTarget, TRY_AGAIN));

    response.setStatus(notice.status());
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setContentType(MediaType.TEXT_HTML_VALUE);
    response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    response.getWriter().write(page);
  }

  private static String anchor(final String href, final String text) {
    return "<a href=\"%s\">%s</a>"
        .formatted(HtmlUtils.htmlEscape(href), HtmlUtils.htmlEscape(text));
  }

  /**
   * Logs the error code, which is a short registered value, never the description: an ID-token
   * validation failure puts the token's claims, such as organization ids, into the description.
   */
  private static void logFailure(
      final HttpServletRequest request, final AuthenticationException exception) {
    final String reason =
        exception instanceof final OAuth2AuthenticationException e && e.getError() != null
            ? e.getError().getErrorCode()
            : exception.getClass().getName();
    LOG.warn(
        "OIDC login failed at '{}' ({}).",
        sanitizeForLog(request.getRequestURI()),
        sanitizeForLog(reason));
  }

  private static boolean isAuthorizationRequestNotFound(final AuthenticationException exception) {
    return exception instanceof final OAuth2AuthenticationException e
        && e.getError() != null
        && AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE.equals(e.getError().getErrorCode());
  }

  /** Matches a request whose Accept header prefers HTML; a bare {@code *}{@code /*} does not. */
  private static MediaTypeRequestMatcher browserRequestMatcher() {
    final MediaTypeRequestMatcher matcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
    matcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
    return matcher;
  }
}
