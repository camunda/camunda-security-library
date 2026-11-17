/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.core.port.out.MembershipPort;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * The settings of {@code username-claim}, {@code client-id-claim} and {@code prefer-username-claim}
 * that tell a user token from a machine token, for each identity provider in scope.
 *
 * <p>A user token here is an access token from the authorization code flow with PKCE of a public or
 * hybrid client. A machine token is an access token from the client credentials flow. Both reach
 * the same API chain, and {@link LazyTokenClaimsConverter} must give the first one a user principal
 * and the second one a client principal.
 *
 * <p>Each identity provider gets one test for the recommended settings and one test for the
 * settings that look correct but fail. The failing test states the reason the recommendation
 * exists. The token shapes come from the documentation of each provider. The Keycloak shapes are
 * also measured against a real server in {@code KeycloakUserBearerTokenIT}.
 *
 * <p>See ADR-0048 and {@code docs/adopters/security-filter-chains.md}.
 */
@ExtendWith(MockitoExtension.class)
class IdpTokenShapePrincipalResolutionTest {

  @Mock private MembershipPort membershipPort;

  private LazyTokenClaimsConverter converter(
      final String usernameClaim, final String clientIdClaim, final boolean preferUsernameClaim) {
    return new LazyTokenClaimsConverter(
        usernameClaim, clientIdClaim, preferUsernameClaim, membershipPort);
  }

  private static Map<String, Object> claims(final Object... keysAndValues) {
    final Map<String, Object> claims = new HashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      claims.put((String) keysAndValues[i], keysAndValues[i + 1]);
    }
    return claims;
  }

  @Nested
  class Keycloak {

    /**
     * Keycloak adds {@code client_id} to a service account token only. It comes from the {@code
     * service_account} client scope, which applies to the client credentials flow alone. A user
     * token carries {@code azp} but no {@code client_id}.
     */
    private Map<String, Object> userToken() {
      return claims(
          "iss", "http://localhost:8080/realms/csl",
          "sub", "f:1b7c:alice",
          "typ", "Bearer",
          "azp", "csl-public",
          "preferred_username", "alice",
          "email", "alice@example.com");
    }

    private Map<String, Object> clientCredentialsToken() {
      return claims(
          "iss", "http://localhost:8080/realms/csl",
          "sub", "f:1b7c:service-account",
          "typ", "Bearer",
          "azp", "csl-hybrid",
          "client_id", "csl-hybrid",
          "preferred_username", "service-account-csl-hybrid");
    }

    /**
     * The recommended settings. {@code client_id} is a machine-only claim, so the user name claim
     * never has to separate anything, and it can stay on the stable {@code sub}. This is the
     * default user name claim of CSL.
     */
    @Test
    void theStableSubSeparatesBothTokensWhenTheClientIdClaimIsMachineOnly() {
      final var converter = converter("sub", "client_id", false);

      assertThat(converter.convert(userToken()).authenticatedUsername()).isEqualTo("f:1b7c:alice");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId())
          .isEqualTo("csl-hybrid");
    }

    /**
     * {@code preferred_username} classifies both tokens correctly too, but a Keycloak user can be
     * renamed, and the principal is the key of every membership and authorization. Prefer {@code
     * sub} unless the deployment keys identity on the user name on purpose.
     */
    @Test
    void preferredUsernameAlsoSeparatesBothTokens() {
      final var converter = converter("preferred_username", "client_id", false);

      assertThat(converter.convert(userToken()).authenticatedUsername()).isEqualTo("alice");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId())
          .isEqualTo("csl-hybrid");
    }

    @Test
    void clientIdClaimOnAzpMakesTheUserTokenAClient() {
      final var converter = converter("preferred_username", "azp", false);

      assertThat(converter.convert(userToken()).authenticatedClientId()).isEqualTo("csl-public");
      assertThat(converter.convert(userToken()).authenticatedUsername()).isNull();
    }

    @Test
    void preferUsernameClaimMakesTheServiceAccountTokenAUser() {
      final var converter = converter("preferred_username", "client_id", true);

      assertThat(converter.convert(clientCredentialsToken()).authenticatedUsername())
          .isEqualTo("service-account-csl-hybrid");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId()).isNull();
    }
  }

  @Nested
  class Entra {

    /**
     * Entra puts {@code azp} in a user token and in an app-only token. Only {@code
     * prefer-username-claim} separates them, with a username claim that an app-only token does not
     * carry. {@code preferred_username} needs the {@code profile} scope, which an app-only token
     * never has.
     */
    private Map<String, Object> userToken() {
      return claims(
          "iss", "https://login.microsoftonline.com/9c2a/v2.0",
          "ver", "2.0",
          "sub", "AAAAAAAA-user-pairwise",
          "oid", "7d4b-user",
          "tid", "9c2a",
          "azp", "11111111-c8ctl",
          "azpacr", "0",
          "preferred_username", "alice@example.com",
          "scp", "Camunda.Access");
    }

    private Map<String, Object> appOnlyToken() {
      return claims(
          "iss", "https://login.microsoftonline.com/9c2a/v2.0",
          "ver", "2.0",
          "sub", "2222-service-principal",
          "oid", "2222-service-principal",
          "tid", "9c2a",
          "azp", "22222222-machine",
          "azpacr", "1",
          "idtyp", "app",
          "roles", List.of("Camunda.Admin"));
    }

    @Test
    void preferUsernameClaimSeparatesBothTokens() {
      final var converter = converter("preferred_username", "azp", true);

      assertThat(converter.convert(userToken()).authenticatedUsername())
          .isEqualTo("alice@example.com");
      assertThat(converter.convert(appOnlyToken()).authenticatedClientId())
          .isEqualTo("22222222-machine");
    }

    @Test
    void withoutPreferUsernameClaimTheUserTokenBecomesAClient() {
      final var converter = converter("preferred_username", "azp", false);

      assertThat(converter.convert(userToken()).authenticatedClientId())
          .isEqualTo("11111111-c8ctl");
      assertThat(converter.convert(userToken()).authenticatedUsername()).isNull();
    }

    @Test
    void usernameClaimOnSubMakesTheAppOnlyTokenAUser() {
      final var converter = converter("sub", "azp", true);

      assertThat(converter.convert(appOnlyToken()).authenticatedUsername())
          .isEqualTo("2222-service-principal");
      assertThat(converter.convert(appOnlyToken()).authenticatedClientId()).isNull();
    }

    /**
     * The limit of the rule on Entra. The stable identifiers of a user, {@code sub} and {@code
     * oid}, are in an app-only token too, where they name the service principal. So no setting both
     * separates the two kinds of token and keys identity on a stable claim. {@code
     * preferred_username} is the only user-only claim, and Microsoft states that it is mutable and
     * must not drive authorization.
     */
    @Test
    void noStableClaimSeparatesBothTokens() {
      final var onOid = converter("oid", "azp", true);

      assertThat(onOid.convert(userToken()).authenticatedUsername()).isEqualTo("7d4b-user");
      assertThat(onOid.convert(appOnlyToken()).authenticatedUsername())
          .as("the app-only token carries oid as well, so it becomes a user")
          .isEqualTo("2222-service-principal");
    }
  }

  @Nested
  class Auth0 {

    /**
     * An Auth0 access token of the default profile carries {@code azp} in both flows, and no claim
     * that only a user has. The two tokens differ in the shape of {@code sub} and in {@code gty},
     * which the resolution does not read. An Auth0 Action must add a claim that only a user token
     * carries.
     *
     * <p>The claim that names the client depends on the token profile of the API. The Auth0 profile
     * emits {@code azp} and no {@code client_id}; the RFC 9068 profile emits {@code client_id} and
     * no {@code azp}. Both are in a user token and in a machine token, so the profile changes the
     * name of the client ID claim and nothing else.
     */
    private Map<String, Object> userToken() {
      return claims(
          "iss", "https://camunda.eu.auth0.com/",
          "sub", "auth0|65f1c3",
          "azp", "c8ctl-public-client",
          "scope", "openid profile");
    }

    private Map<String, Object> clientCredentialsToken() {
      return claims(
          "iss", "https://camunda.eu.auth0.com/",
          "sub", "machine-client@clients",
          "azp", "machine-client",
          "gty", "client-credentials");
    }

    @Test
    void theStockClaimsCannotSeparateTheTwoTokens() {
      final var preferUsername = converter("sub", "azp", true);
      final var preferClientId = converter("sub", "azp", false);

      // Every token has sub, so prefer-username-claim makes the machine token a user.
      assertThat(preferUsername.convert(clientCredentialsToken()).authenticatedUsername())
          .isEqualTo("machine-client@clients");
      // Every token has azp, so the reverse order makes the user token a client.
      assertThat(preferClientId.convert(userToken()).authenticatedClientId())
          .isEqualTo("c8ctl-public-client");
    }

    /** The RFC 9068 profile of the same API, where {@code client_id} replaces {@code azp}. */
    @Test
    void theRfc9068ProfileNamesTheClientWithClientIdInBothTokens() {
      final var userToken = userToken();
      userToken.remove("azp");
      userToken.put("client_id", "c8ctl-public-client");
      final var converter = converter("sub", "client_id", false);

      assertThat(converter.convert(userToken).authenticatedClientId())
          .as("client_id is in a user token too, so the profile changes only the claim name")
          .isEqualTo("c8ctl-public-client");
    }

    @Test
    void aUserOnlyClaimFromAnActionSeparatesBothTokens() {
      final var userToken = userToken();
      userToken.put("https://camunda.com/user_id", "auth0|65f1c3");
      final var converter = converter("https://camunda.com/user_id", "azp", true);

      assertThat(converter.convert(userToken).authenticatedUsername()).isEqualTo("auth0|65f1c3");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId())
          .isEqualTo("machine-client");
    }
  }

  @Nested
  class Okta {

    /**
     * A custom authorization server of Okta puts {@code cid} in both flows and {@code uid} in a
     * user token only, because the client credentials flow binds no user.
     */
    private Map<String, Object> userToken() {
      return claims(
          "iss", "https://camunda.okta.com/oauth2/aus1",
          "sub", "alice@example.com",
          "uid", "00u1alice",
          "cid", "0oa1c8ctl",
          "scp", List.of("camunda.access"));
    }

    private Map<String, Object> clientCredentialsToken() {
      return claims(
          "iss", "https://camunda.okta.com/oauth2/aus1",
          "sub", "0oa1machine",
          "cid", "0oa1machine",
          "scp", List.of("camunda.access"));
    }

    @Test
    void aUserOnlyClaimSeparatesBothTokens() {
      final var converter = converter("uid", "cid", true);

      assertThat(converter.convert(userToken()).authenticatedUsername()).isEqualTo("00u1alice");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId())
          .isEqualTo("0oa1machine");
    }

    @Test
    void usernameClaimOnSubMakesTheMachineTokenAUser() {
      final var converter = converter("sub", "cid", true);

      assertThat(converter.convert(clientCredentialsToken()).authenticatedUsername())
          .isEqualTo("0oa1machine");
    }
  }

  @Nested
  class PingFederate {

    /**
     * An access token manager instance of PingFederate has one attribute contract, and one access
     * token mapping per context: an IdP adapter for a user flow, and the client credentials context
     * for a machine flow. Each mapping fills the same contract from its own source, so an operator
     * leaves the user attribute unfilled in the client credentials mapping. The client ID claim has
     * a configurable name on the Instance Configuration tab, {@code client_id} by default.
     */
    private Map<String, Object> userToken() {
      return claims(
          "iss", "https://pingfederate.example.com",
          "sub", "alice",
          "username", "alice@example.com",
          "client_id", "c8ctl");
    }

    private Map<String, Object> clientCredentialsToken() {
      return claims(
          "iss", "https://pingfederate.example.com",
          "sub", "machine",
          "client_id", "machine");
    }

    @Test
    void aContractWithAUserOnlyAttributeSeparatesBothTokens() {
      final var converter = converter("username", "client_id", true);

      assertThat(converter.convert(userToken()).authenticatedUsername())
          .isEqualTo("alice@example.com");
      assertThat(converter.convert(clientCredentialsToken()).authenticatedClientId())
          .isEqualTo("machine");
    }
  }

  @Nested
  class Defaults {

    /**
     * The defaults are {@code username-claim: sub}, no {@code client-id-claim} and {@code
     * prefer-username-claim: false}. A host that configures nothing gets a user principal for every
     * token, which is what a user Bearer token needs. Such a host cannot recognise a machine token,
     * which is the behaviour before this task.
     */
    @Test
    void aUserBearerTokenResolvesToAUserWithNoClientIdClaimConfigured() {
      final var converter = converter("sub", null, false);

      final var authentication =
          converter.convert(claims("sub", "auth0|65f1c3", "azp", "c8ctl-public-client"));

      assertThat(authentication.authenticatedUsername()).isEqualTo("auth0|65f1c3");
      assertThat(authentication.authenticatedClientId()).isNull();
    }
  }
}
