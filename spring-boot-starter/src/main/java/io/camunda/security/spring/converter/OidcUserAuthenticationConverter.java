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
import io.camunda.security.spring.oidc.ClientRegistrationMetadata;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory;
import io.camunda.security.spring.oidc.TokenValidatorFactory;
import io.camunda.security.spring.oidc.UrlRedaction;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
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
import org.springframework.security.oauth2.jwt.JwtValidationException;

public class OidcUserAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(OidcUserAuthenticationConverter.class);

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
    // Load the authorized client once: its registration holds the login settings of the scope, and
    // a custom OAuth2AuthorizedClientRepository can read it from a remote store.
    final var authorizedClient = getAuthorizedClient(authenticationToken, request);
    // When prefer-id-token-claims is enabled for the current registration we short-circuit the
    // access-token decode path entirely and use the OidcUser principal attributes (which Spring
    // populates with the ID-token and userInfo merged claims). This lets operators opt in to
    // sourcing authorisation-relevant claims from userInfo in setups where the access token is
    // signed by a key set that Camunda cannot reach, or lacks claims Camunda needs.
    if (shouldPreferIdTokenClaims(authenticationToken, authorizedClient)) {
      return getIdTokenClaims(authenticationToken);
    }
    return Optional.ofNullable(getAccessTokenClaims(authenticationToken, authorizedClient))
        .orElseGet(
            () -> {
              LOGGER.warn(
                  "Falling back to ID Token claims for registration '{}'",
                  sanitizeForLog(authenticationToken.getAuthorizedClientRegistrationId()));
              return getIdTokenClaims(authenticationToken);
            });
  }

  private boolean shouldPreferIdTokenClaims(
      final OAuth2AuthenticationToken authenticationToken,
      final OAuth2AuthorizedClient authorizedClient) {
    final var registrationId = authenticationToken.getAuthorizedClientRegistrationId();
    if (registrationId == null) {
      return false;
    }
    return Optional.ofNullable(authorizedClient)
        .map(OAuth2AuthorizedClient::getClientRegistration)
        .flatMap(ClientRegistrationMetadata::preferIdTokenClaims)
        .orElseGet(
            () -> Boolean.TRUE.equals(preferIdTokenClaimsByRegistrationId.get(registrationId)));
  }

  /**
   * Loads the authorized client and decodes its access token.
   *
   * @deprecated {@link #getClaims} no longer calls this method, because it loads the authorized
   *     client once and passes it on. To change the decode, override {@link
   *     #getAccessTokenClaims(OAuth2AuthenticationToken, OAuth2AuthorizedClient)}.
   */
  @Deprecated(since = "1.1.0")
  protected Map<String, Object> getAccessTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    return getAccessTokenClaims(
        authenticationToken, getAuthorizedClient(authenticationToken, request));
  }

  /**
   * Decodes the access token of {@code authorizedClient}, or returns {@code null} when there is
   * none or it does not decode.
   */
  protected Map<String, Object> getAccessTokenClaims(
      final OAuth2AuthenticationToken authenticationToken,
      final OAuth2AuthorizedClient authorizedClient) {
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
      // DEBUG only: the decoder from getAccessTokenClaims already logs the failure at WARN, with
      // the registration that this hook does not get.
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
                + " {}",
            sanitizeForLog(clientRegistration.getRegistrationId()),
            sanitizeForLog(clientRegistration.getClientId()),
            UrlRedaction.redact(issuerForLog(clientRegistration)),
            reasonForLog(e));
        LOGGER.debug("Access Token decode failure", e);
        throw e;
      }
    };
  }

  /**
   * The message of a failed claim check names only the claim. Other failures, for example of the
   * key source, can name the JWK Set URL with credentials in it, so only their type is logged.
   */
  private static String reasonForLog(final JwtException e) {
    return e instanceof JwtValidationException
        ? sanitizeForLog(e.getMessage())
        : e.getClass().getSimpleName();
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
        new DecoderKey(
            clientRegistration.getRegistrationId(),
            details != null ? details.getIssuerUri() : null,
            ClientRegistrationMetadata.issuer(clientRegistration).orElse(null),
            details != null ? details.getJwkSetUri() : null,
            audiences(clientRegistration),
            additionalUris);
    return jwtDecoders.computeIfAbsent(
        key,
        k ->
            accessTokenDecoderFactory.createAccessTokenDecoder(clientRegistration, additionalUris));
  }

  private List<String> additionalJwkSetUris(final ClientRegistration clientRegistration) {
    final var own = ClientRegistrationMetadata.additionalJwkSetUris(clientRegistration);
    if (own.isEmpty()) {
      return additionalJwkSetUris.get(clientRegistration.getRegistrationId());
    }
    // An empty list is the scope's own answer and must not fall back to the lookup.
    return own.get().isEmpty() ? null : own.get();
  }

  private static Set<String> audiences(final ClientRegistration clientRegistration) {
    final var details = clientRegistration.getProviderDetails();
    final var metadata = details != null ? details.getConfigurationMetadata() : null;
    if (metadata != null
        && metadata.get(TokenValidatorFactory.AUDIENCES_METADATA_KEY)
            instanceof final Collection<?> audiences) {
      return audiences.stream().map(String::valueOf).collect(Collectors.toUnmodifiableSet());
    }
    return null;
  }

  private static String issuerForLog(final ClientRegistration clientRegistration) {
    final var details = clientRegistration.getProviderDetails();
    return ClientRegistrationMetadata.issuer(clientRegistration)
        .orElse(details != null ? details.getIssuerUri() : null);
  }

  protected Map<String, Object> getIdTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    return authenticationToken.getPrincipal().getAttributes();
  }

  private record DecoderKey(
      String registrationId,
      String issuerUri,
      String issuerMetadata,
      String jwkSetUri,
      Set<String> audiences,
      List<String> additionalJwkSetUris) {}
}
