/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.jwk.JWK;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.StringUtils;

/**
 * Asks an identity provider whether it accepts a client's credentials, without a user and without
 * side effects: a refresh-token request with a refresh token that does not exist. The token
 * endpoint authenticates the client first (RFC 6749, section 5.2), so it answers {@code
 * invalid_client} (HTTP 401, or 400) for credentials it rejects and {@code invalid_grant} for the
 * unknown refresh token when it accepts them.
 */
public final class ClientCredentialsCheck {

  private static final Pattern ERROR = Pattern.compile("\"error\"\\s*:\\s*\"([^\"]+)\"");
  private static final Duration TIMEOUT = Duration.ofSeconds(10);

  private final HttpClient http;

  public ClientCredentialsCheck() {
    this(HttpClient.newBuilder().connectTimeout(TIMEOUT).build());
  }

  ClientCredentialsCheck(final HttpClient http) {
    this.http = http;
  }

  /**
   * @param jwks the signing key of a {@code private_key_jwt} registration
   */
  public Answer check(
      final ClientRegistration registration, final Function<ClientRegistration, JWK> jwks) {
    final var method = registration.getClientAuthenticationMethod();
    if (ClientAuthenticationMethod.NONE.equals(method)) {
      return new Answer(Verdict.ACCEPTED, "public client, no credentials");
    }
    final var tokenUri = registration.getProviderDetails().getTokenUri();
    if (!StringUtils.hasText(tokenUri)) {
      return new Answer(Verdict.UNKNOWN, "no token endpoint");
    }
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("grant_type", "refresh_token");
    form.put("refresh_token", "credential-check-" + UUID.randomUUID());
    final var request =
        HttpRequest.newBuilder(URI.create(tokenUri))
            .timeout(TIMEOUT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json");
    if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {
      form.put("client_id", registration.getClientId());
      form.put("client_secret", registration.getClientSecret());
    } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)
        || ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(method)) {
      form.put("client_id", registration.getClientId());
      final var assertion =
          new NimbusJwtClientAuthenticationParametersConverter<OAuth2RefreshTokenGrantRequest>(
                  jwks::apply)
              .convert(grantRequest(registration));
      if (assertion != null) {
        assertion.forEach((name, values) -> form.put(name, values.getFirst()));
      }
    } else {
      request.header(
          "Authorization",
          "Basic "
              + Base64.getEncoder()
                  .encodeToString(
                      (encode(registration.getClientId())
                              + ":"
                              + encode(registration.getClientSecret()))
                          .getBytes(StandardCharsets.UTF_8)));
    }
    final HttpResponse<String> response;
    try {
      response =
          http.send(
              request.POST(HttpRequest.BodyPublishers.ofString(formBody(form))).build(),
              HttpResponse.BodyHandlers.ofString());
    } catch (final IOException e) {
      return new Answer(Verdict.UNKNOWN, "token endpoint cannot be reached: " + e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      return new Answer(Verdict.UNKNOWN, "interrupted");
    }
    final var matcher = ERROR.matcher(response.body() == null ? "" : response.body());
    final var error = matcher.find() ? matcher.group(1) : null;
    final var detail = "HTTP " + response.statusCode() + (error == null ? "" : " " + error);
    if (response.statusCode() == 401 || "invalid_client".equals(error)) {
      return new Answer(Verdict.REJECTED, detail);
    }
    if (response.statusCode() / 100 == 2
        || "invalid_grant".equals(error)
        || "unauthorized_client".equals(error)) {
      return new Answer(Verdict.ACCEPTED, detail);
    }
    return new Answer(Verdict.UNKNOWN, detail);
  }

  private static OAuth2RefreshTokenGrantRequest grantRequest(
      final ClientRegistration registration) {
    final var now = Instant.now();
    return new OAuth2RefreshTokenGrantRequest(
        registration,
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, "credential-check", now, now.plusSeconds(1)),
        new OAuth2RefreshToken("credential-check", now));
  }

  private static String formBody(final Map<String, String> form) {
    return form.entrySet().stream()
        .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
        .collect(Collectors.joining("&"));
  }

  private static String encode(final String value) {
    return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
  }

  /** What the identity provider said about the credentials. */
  public enum Verdict {
    ACCEPTED,
    REJECTED,
    /** The provider could not be asked, or gave an answer that does not tell. */
    UNKNOWN
  }

  /**
   * @param detail what the provider answered, without any credential
   */
  public record Answer(Verdict verdict, String detail) {}
}
