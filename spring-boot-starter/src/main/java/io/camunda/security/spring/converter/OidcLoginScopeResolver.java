/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Host-implemented lookup that tells {@link OidcUserAuthenticationConverter} which scope an
 * interactive login belongs to, and which login settings that scope declares. Scope-agnostic: the
 * library treats the scope key as an opaque string and never interprets it.
 *
 * <p>One converter instance serves every scope, and several scopes can share a registration id
 * while differing in issuer, JWKS, audience, additional JWK Set URIs or {@code
 * prefer-id-token-claims}. Keying those settings by registration id alone lets whichever scope logs
 * in first decide them for all the others, so the converter asks this resolver instead.
 */
public interface OidcLoginScopeResolver {

  /**
   * @return the opaque scope key of the login being converted, or {@code null} when the login does
   *     not belong to a scope
   */
  String resolveScope(HttpServletRequest request);

  /**
   * @param scope the key {@link #resolveScope} returned, possibly {@code null}
   * @return the additional JWK Set URIs of the registrations of that scope
   */
  AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris(String scope);

  /**
   * @param scope the key {@link #resolveScope} returned, possibly {@code null}
   * @return the {@code prefer-id-token-claims} setting of the registrations of that scope
   */
  Map<String, Boolean> preferIdTokenClaims(String scope);

  /** A resolver for logins that belong to no scope, using the same settings for every login. */
  static OidcLoginScopeResolver unscoped(
      final AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris,
      final Map<String, Boolean> preferIdTokenClaims) {
    final var uris =
        additionalJwkSetUris != null
            ? additionalJwkSetUris
            : AdditionalJwkSetUrisByRegistrationId.empty();
    final var prefer =
        preferIdTokenClaims != null ? Map.copyOf(preferIdTokenClaims) : Map.<String, Boolean>of();
    return new OidcLoginScopeResolver() {
      @Override
      public String resolveScope(final HttpServletRequest request) {
        return null;
      }

      @Override
      public AdditionalJwkSetUrisByRegistrationId additionalJwkSetUris(final String scope) {
        return uris;
      }

      @Override
      public Map<String, Boolean> preferIdTokenClaims(final String scope) {
        return prefer;
      }
    };
  }
}
