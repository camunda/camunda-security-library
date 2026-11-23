/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The settings of the real identity provider tenants, read from the environment, and the token
 * requests that the live tests make against them.
 *
 * <p>Keycloak runs in a container, so {@code KeycloakUserBearerTokenIT} can make any token it
 * needs. Entra and Auth0 cannot run locally. The live tests therefore call real tenants, and they
 * need credentials that only a scheduled job holds. Every live test asks {@link
 * #entraIsConfigured()} or {@link #auth0IsConfigured()} first and skips itself when the values are
 * absent, so a normal build and a normal {@code ./mvnw verify} on a developer machine are not
 * affected.
 *
 * <p>The two providers make a user token in different ways, because of what their tenants permit.
 *
 * <ul>
 *   <li><b>Auth0</b> uses the resource owner password flow of a test user. Nothing is stored but
 *       the password, and the token is fresh at every run.
 *   <li><b>Entra</b> uses a stored refresh token, because the tenant forces multifactor
 *       registration on a new user and Entra refuses the password flow whenever multifactor is
 *       required. An Entra refresh token of this registration lives 90 days, so it has to be
 *       renewed. {@link #entraUserToken()} says so when the exchange fails.
 * </ul>
 *
 * <p>Neither path runs the authorization code flow with PKCE, because no person is present. That
 * half of the flow stays covered by Keycloak, which runs in a container on every build. These tests
 * cover what Keycloak cannot: the claim shape of a real Entra and a real Auth0 token.
 */
public final class LiveIdpTenants {

  public static final String ENTRA_TENANT_ID = "CSL_ENTRA_TENANT_ID";
  public static final String ENTRA_CLIENT_ID = "CSL_ENTRA_CLIENT_ID";
  public static final String ENTRA_CLIENT_SECRET = "CSL_ENTRA_CLIENT_SECRET";
  public static final String ENTRA_REFRESH_TOKEN = "CSL_ENTRA_REFRESH_TOKEN";

  public static final String AUTH0_DOMAIN = "CSL_AUTH0_DOMAIN";
  public static final String AUTH0_CLIENT_ID = "CSL_AUTH0_CLIENT_ID";
  public static final String AUTH0_CLIENT_SECRET = "CSL_AUTH0_CLIENT_SECRET";
  public static final String AUTH0_AUDIENCE = "CSL_AUTH0_AUDIENCE";
  public static final String AUTH0_TEST_USER = "CSL_AUTH0_TEST_USER";
  public static final String AUTH0_TEST_USER_PASSWORD = "CSL_AUTH0_TEST_USER_PASSWORD";

  private static final ObjectMapper JSON = new ObjectMapper();

  private LiveIdpTenants() {}

  public static boolean entraIsConfigured() {
    return allSet(ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET, ENTRA_REFRESH_TOKEN);
  }

  public static boolean auth0IsConfigured() {
    return allSet(
        AUTH0_DOMAIN,
        AUTH0_CLIENT_ID,
        AUTH0_CLIENT_SECRET,
        AUTH0_AUDIENCE,
        AUTH0_TEST_USER,
        AUTH0_TEST_USER_PASSWORD);
  }

  public static String entraIssuerUri() {
    return "https://login.microsoftonline.com/" + env(ENTRA_TENANT_ID) + "/v2.0";
  }

  /**
   * The audience of an Entra token of this registration is the bare client ID, not the application
   * ID URI that the scope is built from. This is measured, not assumed.
   */
  public static String entraAudience() {
    return env(ENTRA_CLIENT_ID);
  }

  public static String entraClientId() {
    return env(ENTRA_CLIENT_ID);
  }

  public static String entraClientSecret() {
    return env(ENTRA_CLIENT_SECRET);
  }

  /** The app-only token of the client credentials flow. No person is behind it. */
  public static String entraAppOnlyToken() throws Exception {
    return accessTokenOf(
        post(
            entraTokenUri(),
            Map.of(
                "grant_type",
                "client_credentials",
                "client_id",
                env(ENTRA_CLIENT_ID),
                "client_secret",
                env(ENTRA_CLIENT_SECRET),
                "scope",
                "api://" + env(ENTRA_CLIENT_ID) + "/.default")));
  }

  /**
   * The user token, from the stored refresh token of a sign-in that a person made once. The
   * registration is a public client, so the exchange sends no client secret.
   */
  public static String entraUserToken() throws Exception {
    final var response =
        send(
            entraTokenUri(),
            Map.of(
                "grant_type",
                "refresh_token",
                "client_id",
                env(ENTRA_CLIENT_ID),
                "refresh_token",
                env(ENTRA_REFRESH_TOKEN),
                "scope",
                "api://" + env(ENTRA_CLIENT_ID) + "/camunda.api"));
    assertThat(response.statusCode())
        .as(
            "Entra refused the refresh token. It lives 90 days, so it has probably expired: sign"
                + " in once as the test user, take the new refresh token, and replace %s in the"
                + " secret store. The response was: %s",
            ENTRA_REFRESH_TOKEN, response.body())
        .isEqualTo(200);
    return accessTokenOf(response);
  }

  public static String auth0IssuerUri() {
    return "https://" + env(AUTH0_DOMAIN) + "/";
  }

  public static String auth0Audience() {
    return env(AUTH0_AUDIENCE);
  }

  public static String auth0ClientId() {
    return env(AUTH0_CLIENT_ID);
  }

  public static String auth0ClientSecret() {
    return env(AUTH0_CLIENT_SECRET);
  }

  /** The machine token of the client credentials flow. */
  public static String auth0ClientCredentialsToken() throws Exception {
    return accessTokenOf(
        post(
            auth0TokenUri(),
            Map.of(
                "grant_type", "client_credentials",
                "client_id", env(AUTH0_CLIENT_ID),
                "client_secret", env(AUTH0_CLIENT_SECRET),
                "audience", env(AUTH0_AUDIENCE))));
  }

  /**
   * The user token, from the resource owner password flow of the test user. The post-login Action
   * of the tenant runs for this flow as well, so the token carries the user-only claim that the
   * table in ADR-0048 names.
   */
  public static String auth0UserToken() throws Exception {
    return accessTokenOf(
        post(
            auth0TokenUri(),
            Map.of(
                "grant_type", "password",
                "client_id", env(AUTH0_CLIENT_ID),
                "client_secret", env(AUTH0_CLIENT_SECRET),
                "username", env(AUTH0_TEST_USER),
                "password", env(AUTH0_TEST_USER_PASSWORD),
                "audience", env(AUTH0_AUDIENCE),
                "scope", "openid profile email")));
  }

  /**
   * One claim of a token, read without verifying the signature. The chain under test verifies the
   * token; this only reads what the provider put in it, so that an assertion can compare the
   * principal CSL resolved against the claim the token carries.
   */
  public static String claimOf(final String token, final String claim) throws Exception {
    final var value = claimsOf(token).get(claim);
    assertThat(value).as("the token holds no %s claim", claim).isInstanceOf(String.class);
    return (String) value;
  }

  /** Whether the token carries the claim at all, which is what separates the two kinds on Auth0. */
  public static boolean hasClaim(final String token, final String claim) throws Exception {
    return claimsOf(token).containsKey(claim);
  }

  private static Map<?, ?> claimsOf(final String token) throws Exception {
    final var parts = token.split("\\.");
    // Assert on the count and never on the array. A provider that answers with an opaque token
    // fails here, and an assertion over the array would print its segments into a public workflow
    // log and into the uploaded reports.
    assertThat(parts.length).as("the token is not a JSON Web Token").isEqualTo(3);
    return JSON.readValue(new String(Base64.getUrlDecoder().decode(parts[1]), UTF_8), Map.class);
  }

  private static String entraTokenUri() {
    return "https://login.microsoftonline.com/" + env(ENTRA_TENANT_ID) + "/oauth2/v2.0/token";
  }

  private static String auth0TokenUri() {
    return "https://" + env(AUTH0_DOMAIN) + "/oauth/token";
  }

  private static String env(final String name) {
    final var value = System.getenv(name);
    assertThat(value).as("the environment variable %s is not set", name).isNotBlank();
    return value;
  }

  private static boolean allSet(final String... names) {
    return Arrays.stream(names)
        .map(System::getenv)
        .noneMatch(value -> value == null || value.isBlank());
  }

  private static HttpResponse<String> post(final String uri, final Map<String, String> fields)
      throws Exception {
    final var response = send(uri, fields);
    assertThat(response.statusCode())
        .as("the token endpoint refused the request: %s", response.body())
        .isEqualTo(200);
    return response;
  }

  private static HttpResponse<String> send(final String uri, final Map<String, String> fields)
      throws Exception {
    return HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build()
        .send(
            HttpRequest.newBuilder(URI.create(uri))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(form(fields)))
                .build(),
            BodyHandlers.ofString());
  }

  private static String form(final Map<String, String> fields) {
    return new LinkedHashMap<>(fields)
        .entrySet().stream()
            .map(
                entry ->
                    URLEncoder.encode(entry.getKey(), UTF_8)
                        + "="
                        + URLEncoder.encode(entry.getValue(), UTF_8))
            .collect(Collectors.joining("&"));
  }

  private static String accessTokenOf(final HttpResponse<String> response) throws Exception {
    final var token = JSON.readValue(response.body(), Map.class).get("access_token");
    assertThat(token).as("the token response holds no access token").isInstanceOf(String.class);
    return (String) token;
  }
}
