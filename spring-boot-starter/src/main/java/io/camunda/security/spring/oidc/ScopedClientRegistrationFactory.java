/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

/**
 * Builds {@link ClientRegistration} instances from {@link OidcConfiguration} maps. Extracted from
 * {@link OidcBeansConfiguration} so that the creation logic can be reused independently of the
 * Spring bean context. "Scoped" reflects that the factory builds registrations for an arbitrary
 * authentication scope (any per-scope security chain), not only the global configuration — future
 * per-scope chain building reuses this class without modification.
 */
public final class ScopedClientRegistrationFactory {

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map. The map key is used
   * as the {@code registrationId}.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers) {
    return createFromProviderMap(providers, null);
  }

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map, overriding the
   * {@code redirect_uri} for each registration when {@code scopedRedirectUriPath} is non-null and
   * non-blank.
   *
   * <p>The scoped webapp chain's redirection endpoint listens at a prefixed path (e.g. {@code
   * /physical-tenants/<id>/sso-callback}). The registrations built here must carry a matching
   * {@code redirect_uri} so that {@code DefaultOAuth2AuthorizationRequestResolver} sends the
   * correct callback URL to the IdP. Without this override the IdP calls back to the unprefixed
   * cluster path, which the scoped chain never intercepts.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @param scopedRedirectUriPath path component to use as the redirect-uri (e.g. {@code
   *     /physical-tenants/t1/sso-callback}); when {@code null} or blank the redirect-uri from the
   *     {@link OidcConfiguration} is used unchanged
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank but does not start with
   *     '/'
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    Objects.requireNonNull(providers, "providers must not be null");
    // A non-blank path without a leading '/' would produce "{baseUrl}physical-tenants/..." which is
    // not a valid URI — reject it early so the caller gets a clear error instead of a subtle
    // misuse.
    if (StringUtils.hasText(scopedRedirectUriPath) && !scopedRedirectUriPath.startsWith("/")) {
      throw new IllegalArgumentException(
          "scopedRedirectUriPath must start with '/', but was: " + scopedRedirectUriPath);
    }
    return providers.entrySet().stream()
        .map(e -> buildClientRegistration(e.getKey(), e.getValue(), scopedRedirectUriPath))
        .toList();
  }

  /**
   * Flattens an {@link AuthenticationConfiguration} into a provider map keyed by registrationId.
   * The flat {@code oidc.*} block contributes one entry under its {@link
   * OidcConfiguration#getRegistrationId()} when {@code clientId} is set; provider entries from
   * {@code providers.oidc.*} are put on top, so a colliding provider id overwrites the flat entry.
   * This is the single authoritative implementation of the merge rule; {@link
   * OidcAuthenticationConfigurationRepository#initializeProviders} delegates here.
   *
   * @param authentication the authentication configuration to flatten; must not be {@code null}
   * @return a {@link LinkedHashMap} keyed by registrationId; never {@code null}
   */
  public Map<String, OidcConfiguration> flatten(final AuthenticationConfiguration authentication) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var flat = authentication.getOidc();
    final Map<String, OidcConfiguration> result = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      result.put(flat.getRegistrationId(), flat);
    }
    result.putAll(authentication.getProviders().getOidc());
    return result;
  }

  /**
   * Convenience method: flattens the {@link AuthenticationConfiguration} and builds all {@link
   * ClientRegistration} instances from the result.
   *
   * @param authentication the authentication configuration; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> create(final AuthenticationConfiguration authentication) {
    return createFromProviderMap(flatten(authentication));
  }

  /**
   * Builds a single {@link ClientRegistration} from {@link OidcConfiguration}. When {@code
   * issuer-uri} is set, OIDC discovery populates the authorization/token/user-info/jwk-set URIs
   * automatically; any explicitly-configured endpoint URI on {@link OidcConfiguration} then
   * overrides the discovered value. When {@code issuer-uri} is unset, all of authorization-uri,
   * token-uri, and jwk-set-uri must be configured explicitly. The {@code registrationId} argument
   * is the map key in the multi-provider shape and {@link OidcConfiguration#getRegistrationId()} in
   * the legacy flat shape.
   *
   * <p>When {@code scopedRedirectUriPath} is non-null and non-blank, the redirect-uri is set to
   * {@code {baseUrl}<scopedRedirectUriPath>} so it matches the prefixed redirection endpoint of the
   * scoped webapp chain. Spring expands the {@code {baseUrl}} placeholder to the application's base
   * URL — {@code scheme://host:port} plus the servlet context path, if any — at request time.
   */
  private static ClientRegistration buildClientRegistration(
      final String registrationId,
      final OidcConfiguration oidc,
      final String scopedRedirectUriPath) {
    if (!StringUtils.hasText(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId must be non-blank: set"
              + " camunda.security.authentication.oidc.registration-id (flat block)"
              + " or use a non-blank key under"
              + " camunda.security.authentication.providers.oidc.<id>.*");
    }
    final var redirectUri =
        StringUtils.hasText(scopedRedirectUriPath)
            ? "{baseUrl}" + scopedRedirectUriPath
            : oidc.getRedirectUri();
    final ClientRegistration.Builder builder =
        clientRegistrationBuilder(registrationId, oidc)
            .registrationId(registrationId)
            .clientId(oidc.getClientId())
            .clientSecret(oidc.getClientSecret())
            .clientAuthenticationMethod(
                new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .scope(oidc.getScope());
    if (StringUtils.hasText(oidc.getClientName())) {
      builder.clientName(oidc.getClientName());
    }
    if (!oidc.isUserInfoEnabled()) {
      builder.userInfoUri(null);
    }
    return builder.build();
  }

  /**
   * Builds the base {@link ClientRegistration.Builder}: discovery via {@code issuer-uri} when set,
   * otherwise an empty builder; in both cases any explicitly-configured endpoint URI on {@link
   * OidcConfiguration} overrides the discovered value. A non-blank value on the configuration
   * always wins; a null/blank value leaves the discovered value untouched.
   *
   * <p>Mirrors OC's previous {@code ClientRegistrationFactory} so that adopters can rely on
   * explicit overrides to plug gaps in incomplete IdP discovery metadata (older Keycloak realms,
   * custom STS endpoints, proxies that rewrite discovery documents). See
   * camunda/camunda-security-library#233.
   */
  private static ClientRegistration.Builder clientRegistrationBuilder(
      final String registrationId, final OidcConfiguration oidc) {
    final boolean hasIssuer = StringUtils.hasText(oidc.getIssuerUri());
    final ClientRegistration.Builder builder =
        hasIssuer
            ? ClientRegistrations.fromIssuerLocation(oidc.getIssuerUri())
                .registrationId(registrationId)
            : ClientRegistration.withRegistrationId(registrationId);

    if (!hasIssuer
        && (!StringUtils.hasText(oidc.getAuthorizationUri())
            || !StringUtils.hasText(oidc.getTokenUri())
            || !StringUtils.hasText(oidc.getJwkSetUri()))) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
              + " under camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*");
    }

    if (StringUtils.hasText(oidc.getAuthorizationUri())) {
      builder.authorizationUri(oidc.getAuthorizationUri());
    }
    if (StringUtils.hasText(oidc.getTokenUri())) {
      builder.tokenUri(oidc.getTokenUri());
    }
    if (StringUtils.hasText(oidc.getJwkSetUri())) {
      builder.jwkSetUri(oidc.getJwkSetUri());
    }
    if (StringUtils.hasText(oidc.getUserInfoUri())) {
      builder.userInfoUri(oidc.getUserInfoUri());
    }
    if (StringUtils.hasText(oidc.getEndSessionEndpointUri())) {
      // Spring's ClientRegistration carries end_session_endpoint via providerConfigurationMetadata.
      // Setting the map replaces the discovered metadata wholesale, so seed it with only the
      // explicit override; discovery already populated the builder's other endpoints individually.
      builder.providerConfigurationMetadata(
          Map.of("end_session_endpoint", oidc.getEndSessionEndpointUri()));
    }
    return builder;
  }
}
