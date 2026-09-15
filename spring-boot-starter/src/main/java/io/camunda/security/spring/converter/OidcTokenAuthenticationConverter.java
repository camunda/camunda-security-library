/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.context.OidcClaimsProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Converts a Spring Security {@link JwtAuthenticationToken} (the result of a successful OAuth2
 * resource-server bearer-token authentication) into a {@link CamundaAuthentication}.
 *
 * <p>The JWT carries claims, but those claims may not be sufficient to identify the principal — an
 * OIDC provider can return additional claims from its UserInfo endpoint that are not present in the
 * JWT itself. This converter therefore delegates to an {@link OidcClaimsProvider} to obtain the
 * final claims map, then to a {@link LazyTokenClaimsConverter} to map those claims to the {@code
 * CamundaAuthentication} principal, memberships, and raw claims.
 *
 * <p>Plug points for hosts:
 *
 * <ul>
 *   <li>Provide a custom {@link OidcClaimsProvider} bean to augment JWT claims (for example by
 *       merging the UserInfo response). The default {@code NoopOidcClaimsProvider} returns the JWT
 *       claims unchanged.
 *   <li>Provide a {@code MembershipPort} bean — the {@link LazyTokenClaimsConverter} uses it to
 *       resolve the principal's group, role, tenant, and mapping-rule memberships.
 * </ul>
 *
 * <p>This converter is wired into Spring Security via {@code
 * DelegatingCamundaAuthenticationConverter} by registering it as a {@link
 * CamundaAuthenticationConverter} bean. It opts in to handling only {@link JwtAuthenticationToken}
 * instances; non-matching authentications are dispatched to a different converter.
 *
 * <p>A bearer token's {@code iss} claim selects a per-provider claim converter when one is
 * configured; an unrecognized issuer falls back to the default.
 */
public final class OidcTokenAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private final LazyTokenClaimsConverter defaultTokenClaimsConverter;
  private final OidcClaimsProvider claimsProvider;
  private final TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer;

  /**
   * @param defaultTokenClaimsConverter maps the (possibly augmented) claims map to a {@code
   *     CamundaAuthentication}, including principal selection and memberships resolution.
   * @param claimsProvider augments or replaces the JWT claims before they are mapped — for example
   *     by calling the OIDC UserInfo endpoint. Use {@code NoopOidcClaimsProvider} for the JWT-only
   *     behaviour.
   */
  public OidcTokenAuthenticationConverter(
      final LazyTokenClaimsConverter defaultTokenClaimsConverter,
      final OidcClaimsProvider claimsProvider) {
    this(defaultTokenClaimsConverter, claimsProvider, new TokenClaimsConvertersByIssuer(Map.of()));
  }

  /**
   * @param defaultTokenClaimsConverter used when the bearer token's issuer has no entry in {@code
   *     tokenClaimsConvertersByIssuer} — including a missing {@code iss} claim, or a provider
   *     configured without an {@code issuer-uri}.
   * @param claimsProvider augments or replaces the JWT claims before they are mapped — for example
   *     by calling the OIDC UserInfo endpoint. Use {@code NoopOidcClaimsProvider} for the JWT-only
   *     behaviour.
   * @param tokenClaimsConvertersByIssuer per-issuer claim converters, keyed by issuer URI. If
   *     multiple registrations share an issuer, only one occupies that entry.
   */
  public OidcTokenAuthenticationConverter(
      final LazyTokenClaimsConverter defaultTokenClaimsConverter,
      final OidcClaimsProvider claimsProvider,
      final TokenClaimsConvertersByIssuer tokenClaimsConvertersByIssuer) {
    this.defaultTokenClaimsConverter = defaultTokenClaimsConverter;
    this.claimsProvider = claimsProvider;
    this.tokenClaimsConvertersByIssuer =
        tokenClaimsConvertersByIssuer != null
            ? tokenClaimsConvertersByIssuer
            : new TokenClaimsConvertersByIssuer(Map.of());
  }

  @Override
  public boolean supports(final Authentication authentication) {
    return authentication instanceof JwtAuthenticationToken;
  }

  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    try {
      return Optional.of(authentication)
          .map(JwtAuthenticationToken.class::cast)
          .map(JwtAuthenticationToken::getToken)
          .map(
              jwt ->
                  resolveTokenClaimsConverter(jwt)
                      .convert(claimsProvider.claimsFor(jwt.getClaims(), jwt.getTokenValue())))
          .orElseThrow(
              () ->
                  new IllegalStateException(
                      "Failed to convert 'JwtAuthenticationToken' to 'CamundaAuthentication'"));
    } catch (final IllegalArgumentException e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, e.getMessage(), null), e);
    }
  }

  /**
   * Reads the issuer from the raw JWT claims, not the possibly-augmented claims {@link
   * OidcClaimsProvider} produces. {@link Objects#toString(Object, String)} normalizes it regardless
   * of whether the JWT decoder yielded a {@code String} or a {@code java.net.URL}, so the lookup
   * can't miss on type alone.
   */
  private LazyTokenClaimsConverter resolveTokenClaimsConverter(final Jwt jwt) {
    final var issuer = Objects.toString(jwt.getClaims().get(JwtClaimNames.ISS), null);
    return tokenClaimsConvertersByIssuer.getOrDefault(issuer, defaultTokenClaimsConverter);
  }
}
