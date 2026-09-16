/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.stream.Stream;

/**
 * The {@code redirect-uri} values that startup validation accepts, and the values it rejects.
 *
 * <p>Two tests need the same lists. {@link ScopedClientRegistrationFactoryTest} asserts that
 * validation makes the accept-or-reject decision, and {@link OidcRedirectionEndpointTest} asserts
 * that every accepted value expands to a callback the redirection endpoint matches. One source
 * keeps a changed rule from reaching one test only.
 */
final class RedirectUriSamples {

  private RedirectUriSamples() {}

  /** Values that name a callback the application can serve. */
  static Stream<String> usable() {
    return Stream.of(
        "http://localhost/sso-callback",
        "HTTPS://example.com/sso-callback",
        "https://example.com/sso-callback?tenant=a",
        "https://example.com/contextual/sso-callback",
        "https://example.com/context",
        "https://example.com/login/oauth2/code/{registrationId}",
        "{baseUrl}/sso-callback",
        "{baseScheme}://{baseHost}/sso-callback",
        "{baseScheme}://{baseHost}{basePort}{basePath}/sso-callback",
        "https://example.com{basePath}/{action}/sso-callback",
        "{baseUrl}/orchestration/sso-callback",
        "https://example.com{basePath}/orchestration/sso-callback",
        "https://example.com:65535/sso-callback");
  }

  /** Values that give no callback URL the application can serve. */
  static Stream<String> unusable() {
    return Stream.of(
        "http://",
        "https:///sso-callback",
        "ftp://example.com/sso-callback",
        "{baseScheme}:///sso-callback",
        "{baseScheme}://not a host/sso-callback",
        "{baseScheme}://:8080/sso-callback",
        "{baseScheme}://{basePath}/sso-callback",
        "{basePath}/sso-callback",
        "https://example.com/sso-callback#fragment",
        "{baseUrl}#fragment",
        "{baseUrl}",
        "https://example.com",
        "{baseUrl}api/callback",
        "https://example.com/{basePath}/sso-callback",
        "{baseUrl}/{basePath}/sso-callback",
        "{baseUrl}sso-callback",
        "https://example.com:{basePort}/sso-callback",
        "{baseScheme}://{baseHost}:{basePort}/sso-callback",
        "{typo}/sso-callback",
        "https://example.com/{typo}/sso-callback",
        "{baseUrl}/sso/{typo}",
        "https://example.com/sso;callback",
        "https://example.com/sso%3bcallback",
        "https://example.com/sso\\callback",
        "https://example.com/sso%2ecallback",
        "https://example.com/sso%00callback",
        "https://example.com/sso%0acallback",
        "https://example.com/sso%0dcallback",
        "https://example.com/sso%2fcallback",
        "https://example.com/sso%5ccallback",
        "https://example.com/sso%25callback",
        "https://example.com:0/sso-callback",
        "https://example.com:65536/sso-callback");
  }
}
