/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

/**
 * The user Bearer token path on the API chain, against a real Auth0 tenant.
 *
 * <p>An Auth0 access token carries no claim that only a user has. The tenant therefore runs a
 * post-login Action that writes {@value #USER_ID_CLAIM} for user flows only, holding the stable
 * {@code user_id}. That Action is the whole reason the row of ADR-0048 works, so the first test
 * fails the moment someone removes it from the post-login trigger.
 *
 * <p>Both kinds of token carry {@code azp} with the same client ID, so {@code client-id-claim: azp}
 * alone would turn a person into a client. {@code prefer-username-claim: true} is what orders the
 * two checks correctly.
 *
 * <p>The name of the client ID claim follows the JSON Web Token profile of the API: the Auth0
 * profile emits {@code azp} and no {@code client_id}, and the RFC 9068 profile emits {@code
 * client_id} and no {@code azp}. This test runs against an API on the Auth0 profile.
 *
 * <p>The test skips itself when the tenant settings are absent, so a normal build is not affected.
 * {@link LiveIdpTenants} names the variables.
 */
@EnabledIf("io.camunda.security.spring.oidc.LiveIdpTenants#auth0IsConfigured")
final class Auth0LiveUserBearerTokenIT {

  private static final String USER_ID_CLAIM = "https://camunda.io/user_id";

  @Test
  void aUserTokenAuthenticatesAsAUser() throws Exception {
    final var token = LiveIdpTenants.auth0UserToken();

    runner()
        .run(
            ctx -> {
              final var authentication = LiveIdpApiChain.callApiWith(ctx, token);

              assertThat(authentication.authenticatedUsername())
                  .as("the principal must be the claim that the post-login Action adds")
                  .isEqualTo(LiveIdpTenants.claimOf(token, USER_ID_CLAIM));
              assertThat(authentication.authenticatedClientId()).isNull();
              assertThat(authentication.authenticatedRoleIds())
                  .as("memberships must resolve for a Bearer principal")
                  .containsExactly(LiveIdpApiChain.ROLE_OF_A_USER);
            });
  }

  @Test
  void aClientCredentialsTokenStaysAClient() throws Exception {
    final var token = LiveIdpTenants.auth0ClientCredentialsToken();

    runner()
        .run(
            ctx -> {
              final var authentication = LiveIdpApiChain.callApiWith(ctx, token);

              assertThat(authentication.authenticatedClientId())
                  .isEqualTo(LiveIdpTenants.claimOf(token, "azp"));
              assertThat(authentication.authenticatedUsername()).isNull();
            });
  }

  /**
   * The Action is the only thing that separates the two kinds of token on Auth0. A user token that
   * arrives without the claim would resolve to a client, silently, and the person would take the
   * authorizations of the machine caller. This test names that failure, so that a removed or
   * reordered Action is reported as itself.
   */
  @Test
  void theActionAddsTheClaimToAUserTokenOnly() throws Exception {
    final var userToken = LiveIdpTenants.auth0UserToken();
    assertThat(LiveIdpTenants.claimOf(userToken, USER_ID_CLAIM))
        .as("the post-login Action must write the stable user id")
        .isEqualTo(LiveIdpTenants.claimOf(userToken, "sub"));

    assertThat(LiveIdpTenants.hasClaim(LiveIdpTenants.auth0ClientCredentialsToken(), USER_ID_CLAIM))
        .as("a client credentials token must not carry the user claim")
        .isFalse();
  }

  private static WebApplicationContextRunner runner() {
    return LiveIdpApiChain.runner()
        .withPropertyValues(
            "camunda.security.authentication.oidc.type=hybrid",
            "camunda.security.authentication.oidc.client-id=" + LiveIdpTenants.auth0ClientId(),
            "camunda.security.authentication.oidc.client-secret="
                + LiveIdpTenants.auth0ClientSecret(),
            "camunda.security.authentication.oidc.issuer-uri=" + LiveIdpTenants.auth0IssuerUri(),
            "camunda.security.authentication.oidc.audiences=" + LiveIdpTenants.auth0Audience(),
            // The row of ADR-0048 for Auth0, on the Auth0 token profile.
            "camunda.security.authentication.oidc.username-claim=" + USER_ID_CLAIM,
            "camunda.security.authentication.oidc.client-id-claim=azp",
            "camunda.security.authentication.oidc.prefer-username-claim=true");
  }
}
