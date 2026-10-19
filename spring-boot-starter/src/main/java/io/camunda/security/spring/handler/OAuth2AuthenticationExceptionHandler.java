/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.handler;

import static io.camunda.security.spring.oidc.UrlRedaction.escapeControlCharacters;

import io.camunda.security.spring.spi.OidcLoginFailureNotice;
import io.camunda.security.spring.spi.OidcLoginFailurePort;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
 * {@code /<clusterId>} on CCSaaS) would recover to a location outside the application. See ADR-0035
 * for the failed-login page.
 */
public final class OAuth2AuthenticationExceptionHandler implements AuthenticationFailureHandler {

  public static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE =
      "authorization_request_not_found";

  static final String GENERIC_TITLE = "Sign-in failed";
  static final String GENERIC_MESSAGE =
      "We could not sign you in to this application. Your account may not have access to it."
          + " Try again, or contact your administrator if the problem continues.";
  static final String PAGE_TEMPLATE_RESOURCE = "oidc-login-failure-page.html";

  private static final Logger LOG =
      LoggerFactory.getLogger(OAuth2AuthenticationExceptionHandler.class);
  private static final Pattern PLACEHOLDER =
      Pattern.compile("\\{\\{(language|title|message|retryHref|retryText|forwardLink)}}");

  private final AuthenticationFailureHandler delegate;
  private final Supplier<OidcLoginFailurePort> loginFailurePort;
  private final String applicationRoot;
  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  public OAuth2AuthenticationExceptionHandler() {
    this(new SimpleUrlAuthenticationFailureHandler());
  }

  public OAuth2AuthenticationExceptionHandler(final AuthenticationFailureHandler delegate) {
    this(delegate, () -> null, "/");
  }

  /**
   * @param delegate handles failures of non-browser requests
   * @param loginFailurePort resolves the host's explanations, or returns {@code null} for the
   *     generic page only. It is called on each failed login, not here, so a port bean is neither
   *     created nor required while the security chain is built.
   * @param applicationRoot the path, relative to the servlet context, that a stale callback
   *     redirects to and the page links back to: {@code /}, or a scoped chain's {@code
   *     /<basePath>/}
   * @throws IllegalArgumentException if {@code applicationRoot} does not start with {@code /}
   */
  public OAuth2AuthenticationExceptionHandler(
      final AuthenticationFailureHandler delegate,
      final Supplier<OidcLoginFailurePort> loginFailurePort,
      final String applicationRoot) {
    this.delegate = Objects.requireNonNull(delegate, "delegate");
    this.loginFailurePort = Objects.requireNonNull(loginFailurePort, "loginFailurePort");
    Objects.requireNonNull(applicationRoot, "applicationRoot");
    if (!applicationRoot.startsWith("/")) {
      throw new IllegalArgumentException(
          "applicationRoot must start with '/', but was '%s'"
              .formatted(escapeControlCharacters(applicationRoot)));
    }
    this.applicationRoot = applicationRoot;
  }

  @Override
  public void onAuthenticationFailure(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final AuthenticationException exception)
      throws IOException, ServletException {

    if (isAuthorizationRequestNotFound(exception)) {
      redirectStrategy.sendRedirect(request, response, applicationRoot);
      return;
    }

    logFailure(request, exception);
    final Optional<String> pageTemplate = PageTemplate.HTML;
    if (!prefersHtml(request) || response.isCommitted() || pageTemplate.isEmpty()) {
      delegate.onAuthenticationFailure(request, response, exception);
      return;
    }
    renderPage(request, response, pageTemplate.get(), noticeFor(request, exception));
  }

  private OidcLoginFailureNotice noticeFor(
      final HttpServletRequest request, final AuthenticationException exception) {
    try {
      final OidcLoginFailurePort port = loginFailurePort.get();
      if (port != null) {
        final Optional<OidcLoginFailureNotice> notice = port.explain(request, exception);
        if (notice != null && notice.isPresent()) {
          return notice.get();
        }
      }
    } catch (final RuntimeException e) {
      logPortFailure(request, e);
    }
    return new OidcLoginFailureNotice(401, GENERIC_TITLE, GENERIC_MESSAGE);
  }

  /**
   * Logs where a host's port failed, without the exception's message: the port inspects the same
   * exception whose description quotes token claims, so its own message may repeat them. The stack
   * trace, which shows where in the port it failed, is logged at DEBUG on a copy that carries only
   * the exception type.
   */
  private static void logPortFailure(final HttpServletRequest request, final RuntimeException e) {
    LOG.warn(
        "OidcLoginFailurePort failed with {} while explaining a failed OIDC login at '{}'; showing"
            + " the generic failed-login page instead.",
        e.getClass().getName(),
        escapeControlCharacters(request.getRequestURI()));
    if (LOG.isDebugEnabled()) {
      final RuntimeException withoutMessage = new RuntimeException(e.getClass().getName());
      withoutMessage.setStackTrace(e.getStackTrace());
      LOG.debug("Stack trace of the OidcLoginFailurePort failure", withoutMessage);
    }
  }

  private void renderPage(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final String pageTemplate,
      final OidcLoginFailureNotice notice)
      throws IOException {
    final String forwardLink =
        notice.optionalLink().map(link -> anchor(link.target().toString(), link.text())).orElse("");
    final Map<String, String> values =
        Map.of(
            "language", HtmlUtils.htmlEscape(notice.language().toLanguageTag()),
            "title", HtmlUtils.htmlEscape(notice.title()),
            "message", HtmlUtils.htmlEscape(notice.message()),
            "retryHref", HtmlUtils.htmlEscape(request.getContextPath() + applicationRoot),
            "retryText", HtmlUtils.htmlEscape(notice.retryText()),
            "forwardLink", forwardLink);
    // One pass, so a value that happens to contain a placeholder is never substituted again.
    final String page =
        PLACEHOLDER
            .matcher(pageTemplate)
            .replaceAll(placeholder -> Matcher.quoteReplacement(values.get(placeholder.group(1))));

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
        escapeControlCharacters(request.getRequestURI()),
        escapeControlCharacters(reason));
  }

  private static boolean isAuthorizationRequestNotFound(final AuthenticationException exception) {
    return exception instanceof final OAuth2AuthenticationException e
        && e.getError() != null
        && AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE.equals(e.getError().getErrorCode());
  }

  /**
   * Reads a page template from this class's package, or returns empty and logs an ERROR when it is
   * missing or unreadable. Never throws: the page only appears on a failed login, so a missing
   * resource (for example one filtered out of a shaded jar) must not fail the application at
   * startup. Failed logins then get the delegate's plain response instead of the page.
   */
  static Optional<String> loadPageTemplate(final String resource) {
    try (final InputStream template =
        OAuth2AuthenticationExceptionHandler.class.getResourceAsStream(resource)) {
      if (template == null) {
        LOG.error(
            "Missing resource {}; failed OIDC logins get a plain error response instead of the"
                + " failed-login page.",
            resource);
        return Optional.empty();
      }
      return Optional.of(new String(template.readAllBytes(), StandardCharsets.UTF_8));
    } catch (final IOException | UncheckedIOException e) {
      LOG.error(
          "Failed to read resource {}; failed OIDC logins get a plain error response instead of"
              + " the failed-login page.",
          resource,
          e);
      return Optional.empty();
    }
  }

  /**
   * Whether the request's Accept header prefers HTML: HTML is acceptable ({@code q > 0}) and no
   * other type is accepted at a higher quality. A bare {@code *}{@code /*} does not count as asking
   * for HTML, and an exact {@code text/html} entry overrides {@code text/*}. An unparseable header
   * is treated as not preferring HTML, so the request keeps the plain error response.
   */
  static boolean prefersHtml(final HttpServletRequest request) {
    final Enumeration<String> headers = request.getHeaders(HttpHeaders.ACCEPT);
    final List<MediaType> accepted;
    try {
      accepted = MediaType.parseMediaTypes(headers == null ? List.of() : Collections.list(headers));
    } catch (final IllegalArgumentException e) {
      return false;
    }
    double exactHtml = -1;
    double textWildcard = -1;
    double other = 0;
    for (final MediaType type : accepted) {
      final double quality = type.getQualityValue();
      if (type.isWildcardType()) {
        continue;
      }
      if (type.equalsTypeAndSubtype(MediaType.TEXT_HTML)) {
        exactHtml = Math.max(exactHtml, quality);
      } else if (type.includes(MediaType.TEXT_HTML)) {
        textWildcard = Math.max(textWildcard, quality);
      } else {
        other = Math.max(other, quality);
      }
    }
    final double html = exactHtml >= 0 ? exactHtml : textWildcard;
    return html > 0 && html >= other;
  }

  /**
   * The page's markup and styling, kept as a resource so it can be read and edited as HTML. It is
   * styled after the webapps' own forbidden page, and is self-contained: the user has no session,
   * so it cannot load the webapps' assets. Loaded on the first failed login rather than with the
   * handler, by the holder idiom.
   */
  private static final class PageTemplate {
    private static final Optional<String> HTML = loadPageTemplate(PAGE_TEMPLATE_RESOURCE);
  }
}
