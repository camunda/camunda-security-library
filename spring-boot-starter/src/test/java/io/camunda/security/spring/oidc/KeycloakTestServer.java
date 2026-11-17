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

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * One Keycloak for every integration test of this package. The container starts on first use and
 * Testcontainers stops it when the build ends, so the OIDC login tests and the Bearer token tests
 * share one server and one realm import.
 *
 * <p>The realm {@code csl-public} holds the user {@code alice}, a public client that uses the
 * authorization code flow with PKCE, and three confidential clients with a service account. The
 * realm {@code csl-confidential} holds a confidential client for the login tests, and serves as a
 * second issuer.
 *
 * <p>These tests need Docker. {@code ./mvnw verify} runs them, and {@code ./mvnw verify -DskipITs}
 * leaves them out.
 */
public final class KeycloakTestServer {

  public static final String PUBLIC_REALM = "csl-public";
  public static final String CONFIDENTIAL_REALM = "csl-confidential";
  public static final String USERNAME = "alice";
  public static final String PASSWORD = "s3cret";

  private static final Pattern FORM_ACTION = Pattern.compile("action=\"([^\"]+)\"");
  private static final Pattern ACCESS_TOKEN =
      Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
  private static final Pattern EXPIRY = Pattern.compile("\"exp\"\\s*:\\s*(\\d+)");

  private static final GenericContainer<?> KEYCLOAK =
      new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.4"))
          .withExposedPorts(8080)
          .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
          .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
          .withCopyFileToContainer(
              MountableFile.forClasspathResource("keycloak/csl-public-realm.json"),
              "/opt/keycloak/data/import/csl-public-realm.json")
          .withCopyFileToContainer(
              MountableFile.forClasspathResource("keycloak/csl-confidential-realm.json"),
              "/opt/keycloak/data/import/csl-confidential-realm.json")
          .withCommand("start-dev", "--import-realm")
          .waitingFor(
              Wait.forHttp("/realms/" + PUBLIC_REALM + "/.well-known/openid-configuration")
                  .forPort(8080)
                  .forStatusCode(200)
                  .withStartupTimeout(Duration.ofMinutes(3)));

  private KeycloakTestServer() {}

  /** Starts the server if it does not run yet, and returns its base URL. */
  public static synchronized String baseUrl() {
    if (!KEYCLOAK.isRunning()) {
      KEYCLOAK.start();
    }
    return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
  }

  public static String realmUrl(final String realm) {
    return baseUrl() + "/realms/" + realm;
  }

  public static String jwkSetUri(final String realm) {
    return realmUrl(realm) + "/protocol/openid-connect/certs";
  }

  private static String tokenUri(final String realm) {
    return realmUrl(realm) + "/protocol/openid-connect/token";
  }

  /** The access token of a client credentials flow: a machine token with no user behind it. */
  public static String clientCredentialsToken(
      final String realm, final String clientId, final String clientSecret) throws Exception {
    final var form =
        "grant_type=client_credentials"
            + "&client_id="
            + URLEncoder.encode(clientId, UTF_8)
            + "&client_secret="
            + URLEncoder.encode(clientSecret, UTF_8);
    return accessTokenOf(post(tokenUri(realm), form));
  }

  /**
   * The access token of an authorization code flow with PKCE, as c8ctl and Desktop Modeler obtain
   * it. A {@code null} client secret runs the flow as a public client. The test drives the sign-in
   * form of Keycloak itself, so the token has the shape a real login produces.
   */
  public static String authorizationCodeTokenWithPkce(
      final String realm,
      final String clientId,
      final String clientSecret,
      final String redirectUri)
      throws Exception {
    final var verifier = randomVerifier();
    final var authorizationUrl =
        realmUrl(realm)
            + "/protocol/openid-connect/auth?response_type=code"
            + "&client_id="
            + URLEncoder.encode(clientId, UTF_8)
            + "&redirect_uri="
            + URLEncoder.encode(redirectUri, UTF_8)
            + "&scope="
            + URLEncoder.encode("openid profile email", UTF_8)
            + "&code_challenge="
            + challengeOf(verifier)
            + "&code_challenge_method=S256";

    final var callback = signIn(authorizationUrl);
    final var code = queryParameters(callback).get("code");
    assertThat(code).as("Keycloak returned no authorization code").isNotNull();

    var form =
        "grant_type=authorization_code"
            + "&client_id="
            + URLEncoder.encode(clientId, UTF_8)
            + "&redirect_uri="
            + URLEncoder.encode(redirectUri, UTF_8)
            + "&code="
            + URLEncoder.encode(code, UTF_8)
            + "&code_verifier="
            + verifier;
    if (clientSecret != null) {
      form += "&client_secret=" + URLEncoder.encode(clientSecret, UTF_8);
    }
    return accessTokenOf(post(tokenUri(realm), form));
  }

  /**
   * Signs {@link #USERNAME} in at the authorization endpoint and returns the redirect Keycloak
   * sends back to the application. A real HTTP client performs the two steps that belong to the
   * browser alone: the sign-in form, and the redirect that carries the code.
   */
  public static URI signIn(final String authorizationUrl) throws Exception {
    final var http = httpClient();

    final var loginPage =
        http.send(
            HttpRequest.newBuilder(URI.create(authorizationUrl)).GET().build(),
            BodyHandlers.ofString());
    assertThat(loginPage.statusCode()).as("Keycloak served no login page").isEqualTo(200);

    final var form =
        "username="
            + URLEncoder.encode(USERNAME, UTF_8)
            + "&password="
            + URLEncoder.encode(PASSWORD, UTF_8)
            + "&credentialId=";
    final var submitted =
        http.send(
            HttpRequest.newBuilder(URI.create(loginFormAction(loginPage.body())))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Cookie", cookiesOf(loginPage))
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(),
            BodyHandlers.ofString());

    assertThat(submitted.statusCode())
        .as("Keycloak did not sign the user in: %s", submitted.body())
        .isEqualTo(302);
    return URI.create(submitted.headers().firstValue("Location").orElseThrow());
  }

  /**
   * The moment the token expires, read from its {@code exp} claim. The payload is read without
   * verification, which is what a test needs to wait for the expiry of a real token.
   */
  public static Instant expiryOf(final String token) {
    final var payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), UTF_8);
    final var matcher = EXPIRY.matcher(payload);
    assertThat(matcher.find()).as("the token holds no exp claim").isTrue();
    return Instant.ofEpochSecond(Long.parseLong(matcher.group(1)));
  }

  public static Map<String, String> queryParameters(final URI uri) {
    return Arrays.stream(uri.getRawQuery().split("&"))
        .map(pair -> pair.split("=", 2))
        .collect(
            Collectors.toMap(
                pair -> URLDecoder.decode(pair[0], UTF_8),
                pair -> pair.length > 1 ? URLDecoder.decode(pair[1], UTF_8) : ""));
  }

  private static HttpResponse<String> post(final String uri, final String form) throws Exception {
    final var response =
        httpClient()
            .send(
                HttpRequest.newBuilder(URI.create(uri))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build(),
                BodyHandlers.ofString());
    assertThat(response.statusCode())
        .as("the token endpoint refused the request: %s", response.body())
        .isEqualTo(200);
    return response;
  }

  private static String accessTokenOf(final HttpResponse<String> response) {
    final var matcher = ACCESS_TOKEN.matcher(response.body());
    assertThat(matcher.find()).as("the token response holds no access token").isTrue();
    return matcher.group(1);
  }

  private static HttpClient httpClient() {
    return HttpClient.newBuilder()
        .followRedirects(Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }

  /**
   * The cookies of a response, as a request header. Keycloak keeps the state of a login in them,
   * and the {@code CookieManager} of the JDK stores no cookie of a host name without a dot.
   */
  private static String cookiesOf(final HttpResponse<String> response) {
    return response.headers().allValues("set-cookie").stream()
        .map(header -> header.split(";", 2)[0])
        .collect(Collectors.joining("; "));
  }

  private static String loginFormAction(final String html) {
    final var matcher = FORM_ACTION.matcher(html);
    assertThat(matcher.find()).as("no form on the Keycloak login page").isTrue();
    return matcher.group(1).replace("&amp;", "&");
  }

  private static String randomVerifier() {
    final var bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static String challengeOf(final String verifier) throws Exception {
    final var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }
}
