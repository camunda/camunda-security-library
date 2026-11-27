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
 * The user Bearer token path on the API chain, against a real Microsoft Entra ID tenant.
 *
 * <p>This test watches the row of the table in ADR-0048 that Camunda already ships: {@code
 * username-claim: preferred_username}, {@code client-id-claim: azp} and {@code
 * prefer-username-claim: true}. Entra puts {@code azp}, {@code sub} and {@code oid} in a user token
 * and in an app-only token alike, so {@code azp} alone cannot separate them. Only {@code
 * preferred_username} does, and only because a client credentials request can never obtain it.
 * {@code prefer-username-claim: true} is what makes the row work, so the second test fails if that
 * setting ever stops being honoured.
 *
 * <p>The principal of a person is therefore a mutable claim. That is the cost ADR-0048 D1a records,
 * measured against this tenant, not a defect of this test.
 *
 * <p>The test skips itself when the tenant settings are absent, so a normal build is not affected.
 * {@link LiveIdpTenants} names the variables and explains why Entra needs a stored refresh token
 * where Auth0 does not.
 */
@EnabledIf("io.camunda.security.spring.oidc.LiveIdpTenants#entraIsConfigured")
final class EntraLiveUserBearerTokenIT {

  @Test
  void aUserTokenAuthenticatesAsAUser() throws Exception {
    final var token = LiveIdpTenants.entraUserToken();

    runner()
        .run(
            ctx -> {
              final var authentication = LiveIdpApiChain.callApiWith(ctx, token);

              assertThat(authentication.authenticatedUsername())
                  .as("the principal must be the configured user name claim")
                  .isEqualTo(LiveIdpTenants.claimOf(token, "preferred_username"));
              assertThat(authentication.authenticatedClientId()).isNull();
              assertThat(authentication.authenticatedRoleIds())
                  .as("memberships must resolve for a Bearer principal")
                  .containsExactly(LiveIdpApiChain.ROLE_OF_A_USER);
            });
  }

  /**
   * The app-only token carries {@code azp} with the client ID and no {@code preferred_username}, so
   * the chain falls through to the client ID claim and resolves a client. A user token carries
   * {@code azp} as well, which is why the test above matters as much as this one.
   */
  @Test
  void anAppOnlyTokenStaysAClient() throws Exception {
    final var token = LiveIdpTenants.entraAppOnlyToken();

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
   * CSL refuses an Entra token that is not v2.0, so the tenant has to issue v2.0 tokens for the two
   * tests above to mean anything. The registration sets {@code requestedAccessTokenVersion} to 2.
   * This asserts it, so a change at the provider is reported as itself rather than as a puzzling
   * rejection.
   */
  @Test
  void theTenantIssuesVersionTwoTokens() throws Exception {
    assertThat(LiveIdpTenants.claimOf(LiveIdpTenants.entraAppOnlyToken(), "ver"))
        .as("CSL refuses an Entra token that is not v2.0")
        .isEqualTo("2.0");
  }

  private static WebApplicationContextRunner runner() {
    return LiveIdpApiChain.runner()
        .withPropertyValues(
            "camunda.security.authentication.oidc.type=hybrid",
            "camunda.security.authentication.oidc.client-id=" + LiveIdpTenants.entraClientId(),
            "camunda.security.authentication.oidc.client-secret="
                + LiveIdpTenants.entraClientSecret(),
            "camunda.security.authentication.oidc.issuer-uri=" + LiveIdpTenants.entraIssuerUri(),
            "camunda.security.authentication.oidc.audiences=" + LiveIdpTenants.entraAudience(),
            // The row of ADR-0048 that Camunda ships for Entra.
            "camunda.security.authentication.oidc.username-claim=preferred_username",
            "camunda.security.authentication.oidc.client-id-claim=azp",
            "camunda.security.authentication.oidc.prefer-username-claim=true");
  }
}
