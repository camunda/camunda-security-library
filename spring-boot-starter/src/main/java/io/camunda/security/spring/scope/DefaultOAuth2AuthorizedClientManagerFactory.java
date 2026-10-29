/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * The library's {@link OAuth2AuthorizedClientManagerFactory}: authorization code and refresh token,
 * the latter through the scope's own token response client when one is given.
 */
public final class DefaultOAuth2AuthorizedClientManagerFactory
    implements OAuth2AuthorizedClientManagerFactory {

  @Override
  public OAuth2AuthorizedClientManager create(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository) {
    final var manager =
        new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
    manager.setAuthorizedClientProvider(
        OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode().refreshToken().build());
    return manager;
  }

  @Override
  public OAuth2AuthorizedClientManager create(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
          refreshTokenResponseClient) {
    final var manager =
        new DefaultOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);
    manager.setAuthorizedClientProvider(
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken(refresh -> refresh.accessTokenResponseClient(refreshTokenResponseClient))
            .build());
    return manager;
  }
}
