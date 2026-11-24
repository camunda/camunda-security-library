/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds the token request and reads the token response.
 *
 * <p>The response must be strict: {@code Content-Type: application/json}, a non-blank {@code
 * access_token} and {@code token_type} {@code Bearer} (DPoP is not supported, because the client
 * sends no DPoP proof), and a numeric {@code expires_in} if present.
 */
final class TokenResponses {

  private static final Logger LOG = LoggerFactory.getLogger(TokenResponses.class);
  private static final int MAX_DESCRIPTION_LENGTH = 200;

  private TokenResponses() {}

  static HTTPRequest buildRequest(final OidcClientCredentialsConfiguration config) {
    final TokenRequest.Builder builder =
        new TokenRequest.Builder(
            config.tokenUri(),
            new ClientSecretPost(
                new ClientID(config.clientId()), new Secret(config.clientSecret())),
            new ClientCredentialsGrant());
    if (!config.scopes().isEmpty()) {
      builder.scope(new Scope(config.scopes().toArray(new String[0])));
    }
    // Custom parameters, not resources(URI): some IdPs take values that are not URIs.
    putIfPresent(builder, "audience", config.audience());
    putIfPresent(builder, "resource", config.resource());
    final HTTPRequest request = builder.build().toHTTPRequest();
    request.setAccept("application/json");
    request.setConnectTimeout(toMillis(config.connectTimeout()));
    request.setReadTimeout(toMillis(config.readTimeout()));
    request.setFollowRedirects(false);
    return request;
  }

  private static void putIfPresent(
      final TokenRequest.Builder builder, final String name, final String value) {
    if (!ConfigurationChecks.isBlank(value)) {
      builder.customParameter(name, value);
    }
  }

  /** At least 1 ms, because {@code HttpURLConnection} reads 0 as "wait forever". */
  private static int toMillis(final Duration timeout) {
    return (int) Math.max(1L, (timeout.toNanos() + 999_999L) / 1_000_000L);
  }

  static CachedToken parseToken(
      final HTTPResponse response, final Instant sentAt, final String clientId)
      throws TokenRequestException {
    final AccessToken token;
    try {
      token = TokenResponse.parse(response).toSuccessResponse().getTokens().getAccessToken();
    } catch (final ParseException e) {
      // No cause: the Nimbus exception can quote the response body, and so the token.
      throw unusableResponse(e, response.getStatusCode(), clientId);
    }
    // Nimbus parses only Bearer, DPoP and N_A. It rejects other types with a ParseException, and
    // describe() sanitizes that message, so no sanitizing is needed here.
    if (!AccessTokenType.BEARER.equals(token.getType())) {
      throw new TokenRequestException(
          "Token response of client '"
              + clientId
              + "' is not usable: token_type "
              + token.getType().getValue()
              + " is not supported; only Bearer is",
          response.getStatusCode(),
          null,
          null,
          null);
    }
    return CachedToken.of(
        token.toAuthorizationHeader(), token.getValue(), sentAt, token.getLifetime(), clientId);
  }

  private static TokenRequestException unusableResponse(
      final ParseException e, final int status, final String clientId) {
    return new TokenRequestException(
        "Token response of client '" + clientId + "' is not usable: " + describe(e),
        status,
        null,
        null,
        null);
  }

  /**
   * Nimbus names the field that is wrong, not its value. A message that repeats the message of its
   * cause is withheld: the JSON parser quotes the input there, and so maybe the token.
   */
  static String describe(final ParseException e) {
    final String message = e.getMessage();
    final Throwable cause = e.getCause();
    if (message == null
        || cause != null && cause.getMessage() != null && message.contains(cause.getMessage())) {
      return "the response cannot be parsed";
    }
    return sanitize(truncate(message));
  }

  static TokenRequestException failure(final HTTPResponse response, final String clientId) {
    final int status = response.getStatusCode();
    String error = null;
    String description = null;
    try {
      final TokenErrorResponse parsed = TokenErrorResponse.parse(response);
      // Nimbus drops an error code with illegal characters and strips them from the description.
      error = parsed.getErrorObject().getCode();
      description = truncate(parsed.getErrorObject().getDescription());
    } catch (final ParseException | RuntimeException e) {
      LOG.debug(
          "Cannot parse the error response of the token request of client '{}' (HTTP {})",
          clientId,
          status);
    }
    LOG.debug(
        "Token request for client '{}' failed with HTTP {} (error={})", clientId, status, error);
    return new TokenRequestException(
        String.format(
            "Token request for client '%s' failed with HTTP %d (error=%s, error_description=%s)",
            clientId, status, error, description),
        status,
        error,
        description,
        null);
  }

  /** Replaces line breaks and other control characters, so a response cannot forge log lines. */
  private static String sanitize(final String value) {
    return value == null ? null : value.replaceAll("[\\p{Cc}\\u2028\\u2029]", "?");
  }

  private static String truncate(final String value) {
    if (value == null || value.length() <= MAX_DESCRIPTION_LENGTH) {
      return value;
    }
    return value.substring(0, MAX_DESCRIPTION_LENGTH);
  }
}
