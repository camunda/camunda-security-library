/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * The claims that give the principal of a token from one provider. See <a
 * href="https://github.com/camunda/camunda-security-library/blob/main/docs/adr/0034-named-providers-inherit-principal-claims.md">ADR-0034</a>.
 *
 * @param usernameClaim the claim of the user name
 * @param clientIdClaim the claim of the client ID, or {@code null} for no client ID
 * @param preferUsernameClaim whether the user name wins when a token has both claims
 */
public record OidcPrincipalClaims(
    String usernameClaim, @Nullable String clientIdClaim, boolean preferUsernameClaim) {

  /**
   * Returns the principal claims of a provider. For each claim, this uses the value of the provider
   * if it sets one. Else it uses the value of the default slot ({@code oidc.*}), and else the
   * default. A named provider thus uses the global claims, as {@code groups-claim} does.
   *
   * @param provider the configuration of the provider
   * @param defaultSlot the default slot of the same scope, which holds the global claims
   */
  public static OidcPrincipalClaims resolve(
      final OidcConfiguration provider, final OidcConfiguration defaultSlot) {
    Objects.requireNonNull(provider, "provider must not be null");
    Objects.requireNonNull(defaultSlot, "defaultSlot must not be null");
    return new OidcPrincipalClaims(
        provider.isUsernameClaimSet()
            ? provider.getUsernameClaim()
            : defaultSlot.getUsernameClaim(),
        provider.isClientIdClaimSet()
            ? provider.getClientIdClaim()
            : defaultSlot.getClientIdClaim(),
        provider.isPreferUsernameClaimSet()
            ? provider.isPreferUsernameClaim()
            : defaultSlot.isPreferUsernameClaim());
  }
}
