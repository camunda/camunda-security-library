/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import io.camunda.security.spring.oidc.OidcAccessTokenDecoderFactory.OwnedDecoder;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Decodes as its delegate, and returns each token as a {@link VerifiedJwt} with the principal
 * claims of the provider whose registration verified it. The owner comes from the decoder's own
 * routing, and the claims from the providers of the decoder's own scope, so the claim settings of a
 * token never come from a provider that did not verify it.
 */
final class VerifiedJwtDecoder implements JwtDecoder {

  private final JwtDecoder delegate;
  private final Function<String, String> registrationIdByIssuer;
  private final Function<String, OidcPrincipalClaims> principalClaimsByRegistrationId;

  private VerifiedJwtDecoder(
      final OwnedDecoder owned,
      final Function<String, OidcPrincipalClaims> principalClaimsByRegistrationId) {
    delegate = owned.decoder();
    registrationIdByIssuer = owned.registrationIdByIssuer();
    this.principalClaimsByRegistrationId = principalClaimsByRegistrationId;
  }

  /**
   * @param owned the decoder, and the owner of each token as it routes them
   * @param providers the providers of the decoder's scope, keyed by registrationId
   * @param defaultSlot the default slot ({@code oidc.*}) of the scope, whose claims a named
   *     provider inherits
   * @param defaultConverterSlot the provider whose tokens use the default claim converter as they
   *     are, the default slot of the global configuration; {@code null} for none
   */
  static JwtDecoder of(
      final OwnedDecoder owned,
      final Map<String, OidcConfiguration> providers,
      final OidcConfiguration defaultSlot,
      final OidcConfiguration defaultConverterSlot) {
    final var inherited = defaultSlot != null ? defaultSlot : new OidcConfiguration();
    return new VerifiedJwtDecoder(
        owned,
        registrationId -> {
          final var provider = providers.get(registrationId);
          // A registration that no provider describes, such as one a host repository adds, and
          // the default slot of the global configuration use the default converter.
          if (provider == null || provider == defaultConverterSlot) {
            return null;
          }
          return OidcPrincipalClaims.resolve(provider, inherited);
        });
  }

  @Override
  public Jwt decode(final String token) throws JwtException {
    final var jwt = delegate.decode(token);
    final var registrationId =
        registrationIdByIssuer.apply(
            Objects.toString(jwt.getClaims().get(JwtClaimNames.ISS), null));
    return new VerifiedJwt(
        jwt, registrationId != null ? principalClaimsByRegistrationId.apply(registrationId) : null);
  }
}
