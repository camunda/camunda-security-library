/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.oidc.OidcPrincipalLoader;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Converts a {@link JwtAuthenticationToken} into a {@link CamundaAuthentication} using the token's
 * pre-set granted authorities as role IDs and the JWT's raw claims map as the authentication
 * claims.
 *
 * <p>Unlike {@link OidcTokenAuthenticationConverter}, this converter performs no {@code
 * MembershipPort} calls. It is intended for deployments where the JWT itself is the authoritative
 * source of roles — for example, SaaS tokens where an upstream {@code JwtAuthenticationConverter}
 * has already extracted role authorities from a custom claim before this converter runs.
 *
 * <p>Hosts activate this converter by registering it as a {@link
 * io.camunda.security.api.context.CamundaAuthenticationConverter} bean. A host that also imports
 * {@link OidcTokenAuthenticationConverter} must control bean ordering because both converters
 * support {@link JwtAuthenticationToken}.
 */
public final class JwtGrantedAuthoritiesAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private final String usernameClaim;
  private final OidcPrincipalLoader principalLoader;

  /** Resolves the principal from the JWT's {@code sub} claim. */
  public JwtGrantedAuthoritiesAuthenticationConverter() {
    this((String) null);
  }

  /**
   * @param oidcConfiguration supplies the {@code usernameClaim} to resolve the principal from,
   *     keeping this converter's principal resolution consistent with {@link
   *     OidcTokenAuthenticationConverter}'s without the host having to extract the property itself.
   */
  public JwtGrantedAuthoritiesAuthenticationConverter(final OidcConfiguration oidcConfiguration) {
    this(oidcConfiguration.getUsernameClaim());
  }

  /**
   * @param usernameClaim the claim to resolve the principal from — a plain claim name or a JSONPath
   *     expression (see {@link OidcPrincipalLoader}); defaults to the JWT's {@code sub} claim when
   *     {@code null} or blank. Unlike {@code sub}, a claim that is configured but absent, blank, or
   *     not a string fails the token rather than silently falling back to {@code sub} — matching
   *     {@code LazyTokenClaimsConverter}'s behaviour for the same misconfiguration.
   */
  public JwtGrantedAuthoritiesAuthenticationConverter(final String usernameClaim) {
    this.usernameClaim =
        usernameClaim == null || usernameClaim.isBlank()
            ? OidcConfiguration.DEFAULT_USERNAME_CLAIM
            : usernameClaim;
    principalLoader = new OidcPrincipalLoader(this.usernameClaim, null);
  }

  @Override
  public boolean supports(final Authentication authentication) {
    return authentication instanceof JwtAuthenticationToken;
  }

  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    final var token = (JwtAuthenticationToken) authentication;
    final var jwt = token.getToken();
    final String principal;
    try {
      principal = principalLoader.load(jwt.getClaims()).username();
    } catch (final IllegalArgumentException e) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, e.getMessage(), null), e);
    }
    if (principal == null || principal.isBlank()) {
      throw new OAuth2AuthenticationException(
          new OAuth2Error(
              OAuth2ErrorCodes.INVALID_TOKEN,
              "JWT '%s' claim is missing or blank".formatted(usernameClaim),
              null));
    }
    final List<String> roleIds =
        token.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    return CamundaAuthentication.of(
        b -> b.user(principal).roleIds(roleIds).claims(jwt.getClaims()));
  }
}
