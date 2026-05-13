/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaWebappAttributes.POST_LOGOUT_REDIRECT_ATTRIBUTE;
import static io.camunda.security.spring.security.CamundaWebappAttributes.REDIRECT_MESSAGE_ATTRIBUTE;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
 *       CamundaWebappAttributes#POST_LOGOUT_REDIRECT_ATTRIBUTE}, so the host application can
 *       navigate back to the originating page after IdP logout.
 *   <li>Propagates the OIDC user claim {@code login_hint} as a {@code logout_hint} query parameter
 *       to the provider's end-session endpoint when available, so the IdP can terminate the right
 *       session for users with multiple active identities.
 * </ul>
 *
 * <p>The post-logout redirect URL is only accepted when it points back to the same application
 * (same-origin check).
 */
public final class CamundaOidcLogoutSuccessHandler extends OidcClientInitiatedLogoutSuccessHandler {

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

    // Spring returns getDefaultTargetUrl() when no end_session_endpoint is published by the IdP.
    if (Objects.equals(baseLogoutUrl, getDefaultTargetUrl())) {
      LOG.trace(
          "Unable to determine end-session endpoint for OIDC logout. "
              + "The local session has been terminated, but the IdP session will still be active. "
              + "Falling back to '{}' without logout hint.",
          baseLogoutUrl);
      request.setAttribute(REDIRECT_MESSAGE_ATTRIBUTE, END_SESSION_UNAVAILABLE_MESSAGE);
      return baseLogoutUrl;
    }

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
   * Same-origin check for the post-logout redirect URI. The redirect is only honoured when it
   * points back to the same scheme/host/port as the request that triggered logout. Header-injection
   * attempts (CR/LF) and blank values are rejected.
   */
  private static boolean isSameOriginRedirect(final HttpServletRequest request, final String url) {
    if (url == null || url.isBlank()) {
      return false;
    }
    if (url.contains("\r") || url.contains("\n")) {
      return false;
    }
    final String baseUrl =
        UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
            .replacePath(null)
            .replaceQuery(null)
            .fragment(null)
            .build()
            .toUriString();
    return url.startsWith(baseUrl);
  }
}
