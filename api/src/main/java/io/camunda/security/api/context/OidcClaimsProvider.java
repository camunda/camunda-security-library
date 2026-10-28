/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.context;

import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Resolves the final claims map used for authentication from a validated JWT's claims and raw token
 * value. Implementations may augment JWT claims with a UserInfo response. Fail-open implementations
 * return JWT-only claims on failure; fail-closed implementations propagate exceptions.
 */
public interface OidcClaimsProvider {

  Map<String, Object> claimsFor(Map<String, Object> jwtClaims, String tokenValue);

  /**
   * As {@link #claimsFor(Map, String)}, for a token whose decoder recorded the UserInfo use of the
   * provider that verified it. A decoder of one scope does this, because one claims provider serves
   * all scopes, and would otherwise pick a provider of another scope by the token's issuer.
   *
   * <p>The default ignores the decision, so an implementation that predates it keeps its behavior.
   *
   * @param userInfoEnabled whether the provider that verified the token uses UserInfo
   * @param userInfoUri the UserInfo endpoint of the registration that verified the token, or {@code
   *     null} when it exposes none
   */
  default Map<String, Object> claimsFor(
      final Map<String, Object> jwtClaims,
      final String tokenValue,
      final boolean userInfoEnabled,
      final @Nullable String userInfoUri) {
    return claimsFor(jwtClaims, tokenValue);
  }
}
