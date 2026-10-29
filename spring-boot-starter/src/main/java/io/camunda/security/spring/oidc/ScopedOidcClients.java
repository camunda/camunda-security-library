/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * The OAuth2 client stack of one scope generation: its client registrations, the session's
 * authorized clients bound to them, the manager that refreshes their tokens, and the token endpoint
 * of its logins — all authenticating with this generation's credentials.
 *
 * <p>Everything here is built from the generation's provider configuration and referenced only by
 * that generation's chains, so a replaced or removed scope leaves none of it behind, and a scope
 * whose credentials were rotated authenticates every token request — login, refresh and revocation
 * — with the new ones (ADR-0040).
 */
public final class ScopedOidcClients {

  private final LazyClientRegistrationRepository registrations;
  private final OAuth2AuthorizedClientRepository authorizedClients;
  private final OAuth2AuthorizedClientManager authorizedClientManager;
  private final ScopedAssertionJwks assertionJwks;

  private ScopedOidcClients(
      final LazyClientRegistrationRepository registrations,
      final OAuth2AuthorizedClientManagerFactory managerFactory,
      final ScopedAssertionJwks assertionJwks) {
    this.registrations = registrations;
    this.assertionJwks = assertionJwks;
    authorizedClients =
        new CurrentRegistrationAuthorizedClientRepository(
            new HttpSessionOAuth2AuthorizedClientRepository(), registrations);
    authorizedClientManager =
        managerFactory.create(registrations, authorizedClients, refreshTokenResponseClient());
  }

  /** The stack of a scope's login chain, whose registrations carry the scope's login routes. */
  public static ScopedOidcClients forLogin(
      final ScopedClientRegistrationFactory registrationFactory,
      final Map<String, OidcConfiguration> providers,
      final String redirectUriPath,
      final String scopeDescription,
      final OAuth2AuthorizedClientManagerFactory managerFactory) {
    return new ScopedOidcClients(
        new LazyClientRegistrationRepository(
            registrationFactory, providers, redirectUriPath, scopeDescription),
        managerFactory,
        new ScopedAssertionJwks(providers));
  }

  /**
   * The stack of a scope's API chain, which refreshes the tokens of a session but logs no one in.
   */
  public static ScopedOidcClients withoutLoginRoutes(
      final ScopedClientRegistrationFactory registrationFactory,
      final Map<String, OidcConfiguration> providers,
      final String scopeDescription,
      final OAuth2AuthorizedClientManagerFactory managerFactory) {
    return new ScopedOidcClients(
        LazyClientRegistrationRepository.withoutLoginRoutes(
            registrationFactory, providers, scopeDescription),
        managerFactory,
        new ScopedAssertionJwks(providers));
  }

  public LazyClientRegistrationRepository registrations() {
    return registrations;
  }

  public OAuth2AuthorizedClientRepository authorizedClients() {
    return authorizedClients;
  }

  public OAuth2AuthorizedClientManager authorizedClientManager() {
    return authorizedClientManager;
  }

  public ScopedAssertionJwks assertionJwks() {
    return assertionJwks;
  }

  /**
   * The token endpoint of the scope's logins: the authorization code is exchanged with this
   * generation's client secret or {@code private_key_jwt} key, and with the {@code resource} the
   * authorization request carried (RFC 8707).
   */
  public Customizer<OAuth2LoginConfigurer<HttpSecurity>.TokenEndpointConfig> tokenEndpoint() {
    return config -> {
      final var client = new RestClientAuthorizationCodeTokenResponseClient();
      client.addParametersConverter(ScopedOidcClients::resourceParameters);
      client.addParametersConverter(assertionParameters());
      config.accessTokenResponseClient(client);
    };
  }

  /**
   * Resolves the registration of every provider, which fetches the discovery document of each
   * provider configured by its issuer. Returns the failure of each provider that could not be
   * resolved, by registration id; empty when all resolved.
   */
  public Map<String, RuntimeException> resolveAll() {
    final Map<String, RuntimeException> failures = new LinkedHashMap<>();
    for (final var registrationId : registrations.registrationIds()) {
      try {
        Objects.requireNonNull(
            registrations.findByRegistrationId(registrationId),
            () -> "No client registration for registrationId '" + registrationId + "'");
      } catch (final RuntimeException failure) {
        failures.put(registrationId, failure);
      }
    }
    return failures;
  }

  private OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
      refreshTokenResponseClient() {
    final var client = new RestClientRefreshTokenTokenResponseClient();
    client.addParametersConverter(assertionParameters());
    return client;
  }

  private <T extends AbstractOAuth2AuthorizationGrantRequest>
      NimbusJwtClientAuthenticationParametersConverter<T> assertionParameters() {
    final var converter = new NimbusJwtClientAuthenticationParametersConverter<T>(assertionJwks);
    converter.setJwtClientAssertionCustomizer(
        context -> context.getHeaders().algorithm(SignatureAlgorithm.RS256));
    return converter;
  }

  private static MultiValueMap<String, String> resourceParameters(
      final OAuth2AuthorizationCodeGrantRequest request) {
    final var resource =
        request
            .getAuthorizationExchange()
            .getAuthorizationRequest()
            .getAdditionalParameters()
            .get(OAuth2ParameterNames.RESOURCE);
    final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
    if (resource instanceof final Collection<?> values) {
      values.forEach(value -> parameters.add(OAuth2ParameterNames.RESOURCE, value.toString()));
    } else if (resource instanceof final String value && !value.isBlank()) {
      parameters.add(OAuth2ParameterNames.RESOURCE, value);
    }
    return parameters.isEmpty() ? null : parameters;
  }
}
