/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Objects;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Hands out a session's authorized clients bound to the scope's current client registration.
 *
 * <p>An {@link OAuth2AuthorizedClient} stored at login keeps the {@link
 * org.springframework.security.oauth2.client.registration.ClientRegistration} of that login, client
 * secret included, and Spring refreshes and revokes its tokens with exactly that registration.
 * After a credential rotation the stored one carries a secret the identity provider no longer
 * accepts. This repository rebinds the client to the registration the scope serves now, so the next
 * token request of an existing session authenticates with the new credential.
 *
 * <p>A client whose registration the scope no longer configures is reported as absent.
 */
public final class CurrentRegistrationAuthorizedClientRepository
    implements OAuth2AuthorizedClientRepository {

  private final OAuth2AuthorizedClientRepository delegate;
  private final ClientRegistrationRepository registrations;

  public CurrentRegistrationAuthorizedClientRepository(
      final OAuth2AuthorizedClientRepository delegate,
      final ClientRegistrationRepository registrations) {
    this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    this.registrations = Objects.requireNonNull(registrations, "registrations must not be null");
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
      final String clientRegistrationId,
      final Authentication principal,
      final HttpServletRequest request) {
    final OAuth2AuthorizedClient stored =
        delegate.loadAuthorizedClient(clientRegistrationId, principal, request);
    if (stored == null) {
      return null;
    }
    final var current = registrations.findByRegistrationId(clientRegistrationId);
    if (current == null) {
      return null;
    }
    if (current == stored.getClientRegistration()) {
      return (T) stored;
    }
    return (T)
        new OAuth2AuthorizedClient(
            current, stored.getPrincipalName(), stored.getAccessToken(), stored.getRefreshToken());
  }

  @Override
  public void saveAuthorizedClient(
      final OAuth2AuthorizedClient authorizedClient,
      final Authentication principal,
      final HttpServletRequest request,
      final HttpServletResponse response) {
    delegate.saveAuthorizedClient(authorizedClient, principal, request, response);
  }

  @Override
  public void removeAuthorizedClient(
      final String clientRegistrationId,
      final Authentication principal,
      final HttpServletRequest request,
      final HttpServletResponse response) {
    delegate.removeAuthorizedClient(clientRegistrationId, principal, request, response);
  }
}
