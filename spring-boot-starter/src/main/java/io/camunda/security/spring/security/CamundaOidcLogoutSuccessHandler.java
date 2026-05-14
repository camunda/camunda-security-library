/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * {@link OidcClientInitiatedLogoutSuccessHandler} customization that:
 *
 * <ul>
 *   <li>Stores a validated {@code Referer} header as the post-logout redirect URI under {@link
 *       #POST_LOGOUT_REDIRECT_ATTRIBUTE}, so the host application can navigate back to the
 *       originating page after IdP logout.
 *   <li>Propagates the OIDC user claim {@code login_hint} as a {@code logout_hint} query parameter
 *       to the provider's end-session endpoint when available, so the IdP can terminate the right
 *       session for users with multiple active identities.
 * </ul>
 *
 * <p>The post-logout redirect URL is only accepted when it points back to the same application
 * (same-origin check).
 */
public final class CamundaOidcLogoutSuccessHandler extends OidcClientInitiatedLogoutSuccessHandler {

  /**
   * Session attribute under which the validated, same-origin {@code Referer} is stored as the
   * post-logout redirect URI. Hosts that render a post-logout page read this attribute via the
   * constant to keep the contract stable.
   */
  public static final String POST_LOGOUT_REDIRECT_ATTRIBUTE = "postLogoutRedirect";

  /**
   * Session attribute used to surface a human-readable explanation when RP-initiated logout cannot
   * reach the IdP (for example, no {@code end_session_endpoint} was published). Stored on the
   * session — not the request — so the message survives the redirect that the {@link
   * LogoutSuccessHandler} issues and is readable by the post-logout page on the subsequent request.
   */
  public static final String REDIRECT_MESSAGE_ATTRIBUTE = "redirectMessage";

  private static final Logger LOG = LoggerFactory.getLogger(CamundaOidcLogoutSuccessHandler.class);

  private static final String END_SESSION_UNAVAILABLE_MESSAGE =
      "The identity provider's end_session_endpoint is not available. "
          + "The local session has been terminated, but the IdP session will still be active.";

  private final ClientRegistrationRepository clientRegistrationRepository;

  public CamundaOidcLogoutSuccessHandler(
      final ClientRegistrationRepository clientRegistrationRepository) {
    super(clientRegistrationRepository);
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  @Override
  protected String determineTargetUrl(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {

    final String referer = request.getHeader(HttpHeaders.REFERER);
    if (isSameOriginRedirect(request, referer)) {
      request.getSession().setAttribute(POST_LOGOUT_REDIRECT_ATTRIBUTE, referer);
    }

    final String baseLogoutUrl = super.determineTargetUrl(request, response, authentication);

    // Validate the auth context first. Spring's super.determineTargetUrl returns
    // getDefaultTargetUrl() for ANY non-OIDC authentication context (non-OAuth2, non-OidcUser, or
    // unknown registration), not just for a missing end_session_endpoint — so the end-session
    // diagnostic must only fire once we know we're looking at a valid OIDC session.
    if (!(authentication instanceof final OAuth2AuthenticationToken oauth)) {
      LOG.trace(
          "Authentication is not of type OAuth2AuthenticationToken: '{}'. "
              + "Falling back to '{}' without logout hint.",
          authentication,
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    final String registrationId = oauth.getAuthorizedClientRegistrationId();
    final ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationId);

    if (clientRegistration == null) {
      LOG.trace(
          "No client registration found for id '{}'. Falling back to '{}' without logout hint.",
          registrationId,
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    if (!(oauth.getPrincipal() instanceof final OidcUser oidcUser)) {
      LOG.trace(
          "Principal is not of type OidcUser: '{}'. Falling back to '{}' without logout hint.",
          oauth.getPrincipal(),
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    // With a confirmed OIDC session in hand, an equality with getDefaultTargetUrl() can be
    // attributed to the IdP not publishing end_session_endpoint in its discovery metadata.
    if (Objects.equals(baseLogoutUrl, getDefaultTargetUrl())) {
      LOG.trace(
          "Unable to determine end-session endpoint for OIDC logout. "
              + "The local session has been terminated, but the IdP session will still be active. "
              + "Falling back to '{}' without logout hint.",
          baseLogoutUrl);
      request
          .getSession()
          .setAttribute(REDIRECT_MESSAGE_ATTRIBUTE, END_SESSION_UNAVAILABLE_MESSAGE);
      return baseLogoutUrl;
    }

    final String logoutHint = oidcUser.getClaim("login_hint");
    if (logoutHint == null) {
      LOG.trace(
          "No 'login_hint' claim found in OIDC user. Falling back to '{}' without logout hint.",
          baseLogoutUrl);
      return baseLogoutUrl;
    }

    return UriComponentsBuilder.fromUriString(baseLogoutUrl)
        .queryParam("logout_hint", logoutHint)
        .build()
        .toUriString();
  }

  /**
   * Same-origin check for the post-logout redirect URI. The redirect is only honoured when its
   * scheme, host, and effective port (default ports normalised) match those of the request that
   * triggered logout. Header-injection attempts (CR/LF), blank values, and non-absolute or
   * unparseable URLs are rejected.
   *
   * <p>Explicit scheme/host/port comparison is used rather than a prefix check on the base URL — a
   * {@code startsWith}-style check is vulnerable to host-confusion bypasses such as {@code
   * https://app.example.com.evil.com/} and {@code https://app.example.com@evil.com/}.
   */
  private static boolean isSameOriginRedirect(final HttpServletRequest request, final String url) {
    if (url == null || url.isBlank() || url.indexOf('\r') >= 0 || url.indexOf('\n') >= 0) {
      return false;
    }
    final URI candidate;
    final URI requestUri;
    try {
      candidate = new URI(url);
      requestUri = new URI(UrlUtils.buildFullRequestUrl(request));
    } catch (final URISyntaxException ignored) {
      return false;
    }
    if (!candidate.isAbsolute() || candidate.getHost() == null) {
      return false;
    }
    // URI scheme (RFC 3986 §3.1) and DNS host names are case-insensitive — compare with
    // equalsIgnoreCase so a referer like HTTPS://Camunda.com/ is not wrongly rejected.
    return equalsIgnoreCase(candidate.getScheme(), requestUri.getScheme())
        && equalsIgnoreCase(candidate.getHost(), requestUri.getHost())
        && effectivePort(candidate) == effectivePort(requestUri);
  }

  private static boolean equalsIgnoreCase(final String a, final String b) {
    return a == null ? b == null : a.equalsIgnoreCase(b);
  }

  private static int effectivePort(final URI uri) {
    if (uri.getPort() != -1) {
      return uri.getPort();
    }
    final String scheme = uri.getScheme();
    if ("http".equalsIgnoreCase(scheme)) {
      return 80;
    }
    if ("https".equalsIgnoreCase(scheme)) {
      return 443;
    }
    return -1;
  }
}
