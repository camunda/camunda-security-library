/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class OidcPrincipalClaimsTest {

  private final OidcConfiguration defaultSlot =
      OidcConfiguration.builder()
          .usernameClaim("preferred_username")
          .clientIdClaim("azp")
          .preferUsernameClaim(true)
          .build();

  @Test
  void shouldUseTheDefaultSlotClaimsWhenTheProviderSetsNone() {
    // given
    final var provider = new OidcConfiguration();

    // when
    final var claims = OidcPrincipalClaims.resolve(provider, defaultSlot);

    // then
    assertThat(claims).isEqualTo(new OidcPrincipalClaims("preferred_username", "azp", true));
  }

  @Test
  void shouldUseTheProviderClaimsWhenItSetsThemAlsoToTheDefaults() {
    // given a provider that sets the defaults on purpose
    final var provider = new OidcConfiguration();
    provider.setUsernameClaim(OidcConfiguration.DEFAULT_USERNAME_CLAIM);
    provider.setClientIdClaim(null);
    provider.setPreferUsernameClaim(false);

    // when
    final var claims = OidcPrincipalClaims.resolve(provider, defaultSlot);

    // then
    assertThat(claims)
        .isEqualTo(new OidcPrincipalClaims(OidcConfiguration.DEFAULT_USERNAME_CLAIM, null, false));
  }

  @Test
  void shouldResolveEachClaimOnItsOwn() {
    // given a provider that sets only its username claim
    final var provider = OidcConfiguration.builder().usernameClaim("upn").build();

    // when
    final var claims = OidcPrincipalClaims.resolve(provider, defaultSlot);

    // then
    assertThat(claims).isEqualTo(new OidcPrincipalClaims("upn", "azp", true));
  }

  @Test
  void shouldUseTheLibraryDefaultsWhenNoneSetsAClaim() {
    // when
    final var claims =
        OidcPrincipalClaims.resolve(new OidcConfiguration(), new OidcConfiguration());

    // then
    assertThat(claims)
        .isEqualTo(new OidcPrincipalClaims(OidcConfiguration.DEFAULT_USERNAME_CLAIM, null, false));
  }
}
