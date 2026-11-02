/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import com.nimbusds.jose.jwk.JWK;
import io.camunda.security.spring.oidc.FailureDescription;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.client.RestClient;

/**
 * Revokes the session's OAuth2 refresh token at the provider's RFC 7009 revocation endpoint when a
 * user logs out (ADR-0036). The request itself is {@link RefreshTokenRevoker}'s, which the
 * session-expiry path shares (ADR-0043).
 *
 * <p>Logout already invalidates the web session, which discards the {@link OAuth2AuthorizedClient}
 * holding the tokens, but that is local: without this handler the refresh token stays usable at the
 * authorization server until its own expiry.
 *
 * <p>Must be registered with {@code
 * org.springframework.security.config.annotation.web.configurers.LogoutConfigurer#addLogoutHandler}
 * rather than as a {@code LogoutSuccessHandler}. {@code LogoutConfigurer} appends its own {@code
 * SecurityContextLogoutHandler} after every handler added that way, so this one still runs while
 * the session — and therefore the authorized client the refresh token lives in — is readable. A
 * success handler runs after that invalidation, when the token is already gone.
 *
 * <p>Every failure is fail-soft, see {@link RefreshTokenRevoker}: losing a local session the user
 * asked to end must never depend on the IdP being reachable.
 */
public final class RefreshTokenRevocationLogoutHandler implements LogoutHandler {

  private static final Logger LOG =
      LoggerFactory.getLogger(RefreshTokenRevocationLogoutHandler.class);

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final RefreshTokenRevoker revoker;

  /**
   * @param jwkResolver supplies the signing key for an assertion-authenticated client, or {@code
   *     null} when the deployment has no assertion configuration to resolve one from
   */
  public RefreshTokenRevocationLogoutHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final Function<ClientRegistration, JWK> jwkResolver) {
    this(
        clientRegistrationRepository,
        authorizedClientRepository,
        new RefreshTokenRevoker(jwkResolver));
  }

  // Visible for testing: lets a test drive the handler against a MockRestServiceServer-backed
  // client without reaching the network.
  RefreshTokenRevocationLogoutHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final Function<ClientRegistration, JWK> jwkResolver,
      final RestClient restClient) {
    this(
        clientRegistrationRepository,
        authorizedClientRepository,
        new RefreshTokenRevoker(jwkResolver, restClient));
  }

  private RefreshTokenRevocationLogoutHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final RefreshTokenRevoker revoker) {
    this.clientRegistrationRepository =
        Objects.requireNonNull(
            clientRegistrationRepository, "clientRegistrationRepository must not be null");
    this.authorizedClientRepository =
        Objects.requireNonNull(
            authorizedClientRepository, "authorizedClientRepository must not be null");
    this.revoker = Objects.requireNonNull(revoker, "revoker must not be null");
  }

  /**
   * A handler that revokes through {@code revoker}. The chain builder shares it with the chain's
   * session-expiry revocation, so both authenticate to the provider in the same way. A factory
   * rather than a constructor, so a {@code null} JWK resolver passed to the public constructor
   * stays unambiguous.
   */
  static RefreshTokenRevocationLogoutHandler sharing(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final RefreshTokenRevoker revoker) {
    return new RefreshTokenRevocationLogoutHandler(
        clientRegistrationRepository, authorizedClientRepository, revoker);
  }

  @Override
  public void logout(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {
    final var safeId =
        authentication instanceof final OAuth2AuthenticationToken oauth
            ? ScopedClientRegistrationFactory.sanitizeForLog(
                oauth.getAuthorizedClientRegistrationId())
            : "<none>";
    try {
      revokeRefreshToken(request, authentication);
    } catch (final RuntimeException e) {
      // Deliberately swallowed: see the class Javadoc on why logout must not depend on the IdP.
      LOG.warn(
          "Failed to revoke the refresh token for OIDC registration '{}' [{}]. The local session is"
              + " still terminated, but the refresh token may remain valid at the identity provider"
              + " until it expires.",
          safeId,
          FailureDescription.describe(e));
    }
  }

  private void revokeRefreshToken(
      final HttpServletRequest request, final Authentication authentication) {
    if (!(authentication instanceof final OAuth2AuthenticationToken oauth)) {
      // The type, never the object: Authentication#toString renders the principal and the
      // authorities, and CSL must not log PII at any level.
      LOG.trace(
          "Authentication is not an OAuth2AuthenticationToken but '{}'. Nothing to revoke.",
          authentication == null ? "null" : authentication.getClass().getName());
      return;
    }

    final String registrationId = oauth.getAuthorizedClientRegistrationId();
    final ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationId);
    if (clientRegistration == null) {
      LOG.trace(
          "No client registration found for id '{}'. Nothing to revoke.",
          ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
      return;
    }

    revoker.revoke(
        clientRegistration,
        () -> authorizedClientRepository.loadAuthorizedClient(registrationId, oauth, request));
  }
}
