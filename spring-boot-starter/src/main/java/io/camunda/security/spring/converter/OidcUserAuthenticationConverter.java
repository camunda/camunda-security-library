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
import io.camunda.security.spring.spi.OidcLoginScopePort;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
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

  private static final Logger LOGGER =
      LoggerFactory.getLogger(OidcUserAuthenticationConverter.class);

  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final OidcAccessTokenDecoderFactory accessTokenDecoderFactory;
  private final LazyTokenClaimsConverter tokenClaimsConverter;
  private final HttpServletRequest request;
  private final Map<DecoderKey, JwtDecoder> jwtDecoders;
  private final OidcLoginScopePort scopeResolver;

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
    this(
        OidcLoginScopePort.unscoped(additionalJwkSetUris, preferIdTokenClaimsByRegistrationId),
        authorizedClientRepository,
        accessTokenDecoderFactory,
        tokenClaimsConverter,
        request);
  }

  /**
   * For logins that belong to a scope. The port goes first so that a call ending in {@code null}
   * stays unambiguous against the constructors above.
   */
  protected OidcUserAuthenticationConverter(
      final OidcLoginScopePort scopeResolver,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OidcAccessTokenDecoderFactory accessTokenDecoderFactory,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final HttpServletRequest request) {
    this.authorizedClientRepository = authorizedClientRepository;
    this.accessTokenDecoderFactory = accessTokenDecoderFactory;
    this.tokenClaimsConverter = tokenClaimsConverter;
    this.request = request;
    this.scopeResolver = scopeResolver;
    jwtDecoders = new ConcurrentHashMap<>();
  }

  /**
   * Creates a converter that asks {@code scopePort} which scope a login belongs to and which login
   * settings that scope declares; see {@link OidcLoginScopePort}.
   */
  public static OidcUserAuthenticationConverter scoped(
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OidcAccessTokenDecoderFactory accessTokenDecoderFactory,
      final LazyTokenClaimsConverter tokenClaimsConverter,
      final HttpServletRequest request,
      final OidcLoginScopePort scopePort) {
    return new OidcUserAuthenticationConverter(
        scopePort,
        authorizedClientRepository,
        accessTokenDecoderFactory,
        tokenClaimsConverter,
        request);
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
                  "Falling back to ID Token claims for registration '{}' in scope '{}'",
                  sanitizeForLog(authenticationToken.getAuthorizedClientRegistrationId()),
                  sanitizeForLog(currentScope()));
              return getIdTokenClaims(authenticationToken);
            });
  }

  private boolean shouldPreferIdTokenClaims(final OAuth2AuthenticationToken authenticationToken) {
    final var registrationId = authenticationToken.getAuthorizedClientRegistrationId();
    return registrationId != null
        && Boolean.TRUE.equals(
            scopeResolver.preferIdTokenClaims(currentScope()).get(registrationId));
  }

  protected Map<String, Object> getAccessTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    final var authorizedClient = getAuthorizedClient(authenticationToken, request);
    return Optional.ofNullable(authorizedClient)
        .map(OAuth2AuthorizedClient::getAccessToken)
        .map(OAuth2AccessToken::getTokenValue)
        .map(
            tokenValue -> {
              final var clientRegistration = authorizedClient.getClientRegistration();
              final var jwtDecoder = getJwtDecoder(clientRegistration);
              return decodeAccessToken(
                  loggingFailures(jwtDecoder, clientRegistration.getRegistrationId()), tokenValue);
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
      LOGGER.debug("Failed to decode Access Token: '{}', returning null", e.getMessage());
      return null;
    }
  }

  /**
   * Wraps the decoder handed to {@link #decodeAccessToken} so a failure is logged at WARN with the
   * registration and the scope, which that hook does not receive. Hosts that override the hook
   * still get the wrapper as their decoder.
   */
  private JwtDecoder loggingFailures(final JwtDecoder jwtDecoder, final String registrationId) {
    return token -> {
      try {
        return jwtDecoder.decode(token);
      } catch (final JwtException e) {
        LOGGER.warn(
            "Failed to decode Access Token for registration '{}' in scope '{}': '{}'",
            sanitizeForLog(registrationId),
            sanitizeForLog(currentScope()),
            e.getMessage());
        throw e;
      }
    };
  }

  protected JwtDecoder getJwtDecoder(final ClientRegistration clientRegistration) {
    return getJwtDecoder(clientRegistration, currentScope());
  }

  private JwtDecoder getJwtDecoder(
      final ClientRegistration clientRegistration, final String scope) {
    final var registrationId = clientRegistration.getRegistrationId();
    final var key = decoderKey(scope, clientRegistration);
    return jwtDecoders.computeIfAbsent(
        key,
        k ->
            accessTokenDecoderFactory.createAccessTokenDecoder(
                clientRegistration, scopeResolver.additionalJwkSetUris(scope).get(registrationId)));
  }

  private static DecoderKey decoderKey(
      final String scope, final ClientRegistration clientRegistration) {
    final var details = clientRegistration.getProviderDetails();
    if (details == null) {
      return new DecoderKey(scope, clientRegistration.getRegistrationId(), null, null, null);
    }
    final var issuer = TokenValidatorFactory.registrationIssuer(clientRegistration).orElse(null);
    return new DecoderKey(
        scope,
        clientRegistration.getRegistrationId(),
        issuer,
        details.getJwkSetUri(),
        details.getConfigurationMetadata().get(TokenValidatorFactory.AUDIENCES_METADATA_KEY));
  }

  private String currentScope() {
    return scopeResolver.resolveScope(request);
  }

  protected Map<String, Object> getIdTokenClaims(
      final OAuth2AuthenticationToken authenticationToken) {
    return authenticationToken.getPrincipal().getAttributes();
  }

  /**
   * Identifies the provider settings a decoder was built from. The scope and the registration's own
   * issuer, JWK Set URI and audiences are part of the key, so scopes that share a registration id
   * never share a decoder.
   */
  private record DecoderKey(
      String scope,
      String registrationId,
      TokenValidatorFactory.RegistrationIssuer issuer,
      String jwkSetUri,
      Object audiences) {}
}
