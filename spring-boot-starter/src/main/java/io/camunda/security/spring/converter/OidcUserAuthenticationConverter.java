/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import static io.camunda.security.spring.oidc.ScopedClientRegistrationFactory.sanitizeForLog;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import io.camunda.security.spring.oidc.UrlRedaction;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

public class OidcUserAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  /**
   * Metadata key for the additional JWK Set URIs of a {@link ClientRegistration}. If the entry
   * exists, it wins over the {@link AdditionalJwkSetUrisByRegistrationId} lookup. Scopes can use
   * the same registration ID with different settings. See <a
   * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0033-login-settings-carried-by-the-registration.md">ADR-0033</a>.
   */
  public static final String ADDITIONAL_JWK_SET_URIS_METADATA_KEY =
      "camunda.security.oidc.additional-jwk-set-uris";

  /**
   * Metadata key for the {@code prefer-id-token-claims} flag of a {@link ClientRegistration}. If
   * the entry exists, it wins over the map from the constructor.
   */
  public static final String PREFER_ID_TOKEN_CLAIMS_METADATA_KEY =
      "camunda.security.oidc.prefer-id-token-claims";

  private static final Logger LOGGER =
      LoggerFactory.getLogger(OidcUserAuthenticationConverter.class);

  private static final String AUTHORIZED_CLIENT_ATTRIBUTE =
      OidcUserAuthenticationConverter.class.getName() + ".AUTHORIZED_CLIENT";

  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final OidcAccessTokenDecoderFactory accessTokenDecoderFactory;
  private final LazyTokenClaimsConverter tokenClaimsConverter;
  private final HttpServletRequest request;
  private final Map<DecoderKey, JwtDecoder> jwtDecoders;
  private final AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris;
  private final Map<String, Boolean> preferIdTokenClaimsByRegistrationId;

  public OidcUserAuthenticationConverter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OidcAccessTokenDecoderFactory accessTokenDecoderFactory,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final HttpServletRequest request) {
    this(
        authorizedClientRepository,
        accessTokenDecoderFactory,
        tokenClaimsConverter,
        request,
        AdditionalJwkSetUrisByRegistrationId.empty(),
        Collections.emptyMap());
  }

  public OidcUserAuthenticationConverter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OidcAccessTokenDecoderFactory accessTokenDecoderFactory,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final HttpServletRequest request,
      final AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris) {
    this(
        authorizedClientRepository,
        accessTokenDecoderFactory,
        tokenClaimsConverter,
        request,
        additionalJwkSetUris,
        Collections.emptyMap());
  }

  public OidcUserAuthenticationConverter(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OidcAccessTokenDecoderFactory accessTokenDecoderFactory,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final HttpServletRequest request,
      final AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris,
      final Map<String, Boolean> preferIdTokenClaimsByRegistrationId) {
    this.authorizedClientRepository = authorizedClientRepository;
    this.accessTokenDecoderFactory = accessTokenDecoderFactory;
    this.tokenClaimsConverter = tokenClaimsConverter;
    this.request = request;
    this.additionalJwkSetUris =
        additionalJwkSetUris != null
            ? additionalJwkSetUris
            : AdditionalJwkSetUrisByRegistrationId.empty();
    this.preferIdTokenClaimsByRegistrationId =
        preferIdTokenClaimsByRegistrationId != null
            ? Map.copyOf(preferIdTokenClaimsByRegistrationId)
            : Collections.emptyMap();
    jwtDecoders = new ConcurrentHashMap<>();
  }

  @Override
  public boolean supports(final Authentication authentication) {
    return Optional.ofNullable(authentication)
        .filter(OAuth2AuthenticationToken.class::isInstance)
        .isPresent();
  }

  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    try {
      return Optional.of(authentication)
          .map(OAuth2AuthenticationToken.class::cast)
          .map(this::getClaims)
          .map(tokenClaimsConverter::convert)
          .orElseThrow(
              () ->
                  new IllegalStateException(
                      "Failed to convert 'OAuth2AuthenticationToken' to 'CamundaAuthentication'"));
    } catch (final IllegalArgumentException e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, e.getMessage(), null), e);
    }
  }

  protected Map<String, Object> getClaims(final OAuth2AuthenticationToken authenticationToken) {
    // When prefer-id-token-claims is enabled for the current registration we short-circuit the
    // access-token decode path entirely and use the OidcUser principal attributes (which Spring
    // populates with the ID-token and userInfo merged claims). This lets operators opt in to
    // sourcing authorisation-relevant claims from userInfo in setups where the access token is
    // signed by a key set that Camunda cannot reach, or lacks claims Camunda needs.
    if (shouldPreferIdTokenClaims(authenticationToken)) {
      return getIdTokenClaims(authenticationToken);
    }
    return Optional.ofNullable(getAccessTokenClaims(authenticationToken))
        .orElseGet(
            () -> {
              LOGGER.warn(
                  "Falling back to ID Token claims for registration '{}'",
                  sanitizeForLog(authenticationToken.getAuthorizedClientRegistrationId()));
              return getIdTokenClaims(authenticationToken);
            });
  }

  private boolean shouldPreferIdTokenClaims(final OAuth2AuthenticationToken authenticationToken) {
    final var registrationId = authenticationToken.getAuthorizedClientRegistrationId();
    if (registrationId == null) {
      return false;
    }
    final var metadata =
        Optional.ofNullable(authorizedClientOnce(authenticationToken))
            .map(OAuth2AuthorizedClient::getClientRegistration)
            .map(OidcUserAuthenticationConverter::metadata)
            .orElse(Map.of());
    if (metadata.containsKey(PREFER_ID_TOKEN_CLAIMS_METADATA_KEY)) {
      final var value = metadata.get(PREFER_ID_TOKEN_CLAIMS_METADATA_KEY);
      if (!(value instanceof final Boolean prefer)) {
        throw new IllegalStateException(
            "Metadata key '" + PREFER_ID_TOKEN_CLAIMS_METADATA_KEY + "' must hold a Boolean");
      }
      return prefer;
    }
    return Boolean.TRUE.equals(preferIdTokenClaimsByRegistrationId.get(registrationId));
  }

  protected Map<String, Object> getAccessTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    final var authorizedClient = authorizedClientOnce(authenticationToken);
    return Optional.ofNullable(authorizedClient)
        .map(OAuth2AuthorizedClient::getAccessToken)
        .map(OAuth2AccessToken::getTokenValue)
        .map(
            tokenValue -> {
              final var clientRegistration = authorizedClient.getClientRegistration();
              final var jwtDecoder = getJwtDecoder(clientRegistration);
              return decodeAccessToken(loggingFailures(jwtDecoder, clientRegistration), tokenValue);
            })
        .map(Jwt::getClaims)
        .orElse(null);
  }

  /**
   * Loads the authorized client of the login only once per request. Both the {@code
   * prefer-id-token-claims} check and the access-token decode need it, and a custom {@link
   * OAuth2AuthorizedClientRepository} can read it from a remote store.
   */
  private OAuth2AuthorizedClient authorizedClientOnce(
      final OAuth2AuthenticationToken authenticationToken) {
    if (request.getAttribute(AUTHORIZED_CLIENT_ATTRIBUTE) instanceof final LoadedClient loaded
        && loaded.authenticationToken() == authenticationToken) {
      return loaded.authorizedClient();
    }
    final var authorizedClient = getAuthorizedClient(authenticationToken, request);
    request.setAttribute(
        AUTHORIZED_CLIENT_ATTRIBUTE, new LoadedClient(authenticationToken, authorizedClient));
    return authorizedClient;
  }

  protected OAuth2AuthorizedClient getAuthorizedClient(
      final OAuth2AuthenticationToken authenticationToken, final HttpServletRequest request) {
    final var clientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
    return authorizedClientRepository.loadAuthorizedClient(
        clientRegistrationId, authenticationToken, request);
  }

  protected Jwt decodeAccessToken(final JwtDecoder jwtDecoder, final String accessTokenValue) {
    try {
      return jwtDecoder.decode(accessTokenValue);
    } catch (final JwtException e) {
      LOGGER.debug("Failed to decode Access Token: '{}', returning null", e.getMessage());
      return null;
    }
  }

  /**
   * Logs a decode failure at WARN with the registration, its client ID and its issuer. Scopes can
   * use the same registration ID and issuer, so the client ID helps to find the scope. The {@link
   * #decodeAccessToken} hook does not get these values. A host that overrides the hook also gets
   * this decoder.
   */
  private static JwtDecoder loggingFailures(
      final JwtDecoder jwtDecoder, final ClientRegistration clientRegistration) {
    return token -> {
      try {
        return jwtDecoder.decode(token);
      } catch (final JwtException e) {
        LOGGER.warn(
            "Failed to decode Access Token for registration '{}' with client '{}' and issuer '{}':"
                + " '{}'",
            sanitizeForLog(clientRegistration.getRegistrationId()),
            sanitizeForLog(clientRegistration.getClientId()),
            UrlRedaction.redact(issuerForLog(clientRegistration)),
            e.getMessage());
        throw e;
      }
    };
  }

  /**
   * Returns one decoder for each different provider setting. Scopes can use the same registration
   * ID with a different issuer, key set or audience. Thus the key holds all settings of the
   * decoder.
   */
  protected JwtDecoder getJwtDecoder(final ClientRegistration clientRegistration) {
    final var additionalUris = additionalJwkSetUris(clientRegistration);
    final var details = clientRegistration.getProviderDetails();
    final var key =
        details == null
            ? new DecoderKey(clientRegistration.getRegistrationId(), null, null, null, null, null)
            : new DecoderKey(
                clientRegistration.getRegistrationId(),
                details.getIssuerUri(),
                TokenValidatorFactory.registrationIssuer(clientRegistration).orElse(null),
                details.getJwkSetUri(),
                metadata(clientRegistration).get(TokenValidatorFactory.AUDIENCES_METADATA_KEY),
                additionalUris);
    return jwtDecoders.computeIfAbsent(
        key,
        k ->
            accessTokenDecoderFactory.createAccessTokenDecoder(clientRegistration, additionalUris));
  }

  private List<String> additionalJwkSetUris(final ClientRegistration clientRegistration) {
    final var metadata = metadata(clientRegistration);
    if (!metadata.containsKey(ADDITIONAL_JWK_SET_URIS_METADATA_KEY)) {
      return additionalJwkSetUris.get(clientRegistration.getRegistrationId());
    }
    final var value = metadata.get(ADDITIONAL_JWK_SET_URIS_METADATA_KEY);
    if (!(value instanceof final Collection<?> uris)
        || uris.stream().anyMatch(uri -> !(uri instanceof String))) {
      throw new IllegalStateException(
          "Metadata key '"
              + ADDITIONAL_JWK_SET_URIS_METADATA_KEY
              + "' must hold a collection of String URIs");
    }
    return uris.isEmpty() ? null : uris.stream().map(String.class::cast).toList();
  }

  private static Map<String, Object> metadata(final ClientRegistration clientRegistration) {
    final var details = clientRegistration.getProviderDetails();
    if (details == null || details.getConfigurationMetadata() == null) {
      return Map.of();
    }
    return details.getConfigurationMetadata();
  }

  private static String issuerForLog(final ClientRegistration clientRegistration) {
    final var details = clientRegistration.getProviderDetails();
    return TokenValidatorFactory.registrationIssuer(clientRegistration)
        .map(TokenValidatorFactory.RegistrationIssuer::uri)
        .orElse(details == null ? null : details.getIssuerUri());
  }

  protected Map<String, Object> getIdTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    return authenticationToken.getPrincipal().getAttributes();
  }

  private record DecoderKey(
      String registrationId,
      String issuerUri,
      TokenValidatorFactory.RegistrationIssuer issuerMetadata,
      String jwkSetUri,
      Object audiences,
      List<String> additionalJwkSetUris) {}

  private record LoadedClient(
      OAuth2AuthenticationToken authenticationToken, OAuth2AuthorizedClient authorizedClient) {}
}
