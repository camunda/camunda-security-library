/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

class OidcRedirectionEndpointTest {

  private static final String SAMPLE_CONTEXT_PATH = "/orchestration";

  // redirection-endpoint path resolution (ADR-0018): configurable callback path

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriUnset() {
    assertThat(OidcRedirectionEndpoint.resolve(null, "", "/sso-callback"))
        .isEqualTo("/sso-callback");
    assertThat(OidcRedirectionEndpoint.resolve("  ", "", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsBaseUrlPlaceholder() {
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "{baseUrl}/api/authentication/callback", "", "/sso-callback"))
        .isEqualTo("/api/authentication/callback");
  }

  @Test
  void redirectionEndpointPathStripsSchemeHostAndQuery() {
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://optimize.example.com/sso-callback?x=1", "", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathRewritesRegistrationIdPlaceholderToWildcard() {
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "{baseUrl}/login/oauth2/code/{registrationId}", "", "/sso-callback"))
        .isEqualTo("/login/oauth2/code/*");
  }

  @Test
  void redirectionEndpointPathRejectsResolvedPathWithoutLeadingSlash() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> OidcRedirectionEndpoint.resolve("{baseUrl}api/callback", "", "/sso-callback"))
        .withMessageContaining("must resolve to a path starting with '/'")
        .withMessageContaining("api/callback");
  }

  // GH-569 regression: a redirect-uri that embeds the servlet context-path must yield a
  // context-relative callback path, or Spring's redirection-endpoint matcher (which matches the
  // context-path-stripped request path) never fires and the OIDC login loops indefinitely.

  @Test
  void redirectionEndpointPathStripsContextPathFromAbsoluteRedirectUri() {
    // given an absolute redirect-uri whose path embeds the /orchestration context-path (what the
    // Camunda 8.10 chart renders for a context-path'd webapp)
    // when resolved with that context-path
    // then only the context-relative callback path remains
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsASegmentTheContextPathPlaceholderAlreadyAccountsFor() {
    // given a {baseUrl} template whose own path repeats the context-path segment, so the callback
    // the IdP is handed sits at /orchestration/orchestration/sso-callback
    // when resolved under that context-path
    // then only the servlet's context-path is taken off, which {baseUrl} already stands for — the
    // repeated segment is part of the callback and stays, or the endpoint would listen one segment
    // above where the browser lands
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "{baseUrl}/orchestration/sso-callback", "/orchestration", "/sso-callback"))
        .isEqualTo("/orchestration/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsASegmentTheBasePathPlaceholderAlreadyAccountsFor() {
    // given the same shape spelled out with {basePath} instead of {baseUrl}
    // when resolved under that context-path
    // then the repeated segment stays for the same reason
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com{basePath}/orchestration/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/orchestration/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsContextPathOnlyOnWholeSegments() {
    // given a context-path that is a string prefix of a longer first segment
    // when resolved
    // then the partial match is not stripped
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration-ui/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/orchestration-ui/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsPathWhenContextPathNotEmbedded() {
    // given a root-registered redirect-uri (Optimize CCSaaS: built from the base host, no
    // clusterId prefix) while the app runs under a context-path
    // when resolved
    // then the callback path is untouched (Spring strips the context-path at request time)
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/sso-callback?uuid=cluster-1",
                "/cluster-1",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriIsExactlyContextPath() {
    // given a redirect-uri whose whole path is the context-path (no callback segment)
    // when resolved
    // then it falls back to the default rather than yielding a blank matcher
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsContextPathWhenContextPathPropertyHasTrailingSlash() {
    // given the servlet context-path property itself carries a trailing slash (a value an operator
    // may set, e.g. server.servlet.context-path=/orchestration/) against a normal redirect-uri
    // when resolved
    // then stripContextPath normalizes the context-path and still yields the context-relative
    // callback
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/sso-callback",
                "/orchestration/",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriIsContextPathWithTrailingSlash() {
    // given a redirect-uri whose whole path is the context-path with a trailing slash (a common
    // operator variant of "context root, no callback segment")
    // when resolved
    // then it falls back to the default just like the exact-match case, rather than stripping to a
    // "/" matcher that would never match the real callback and reintroduce the login loop
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  // Both sides are derived from the real components, so a redirect-uri shape one supports and the
  // other does not fails here rather than at login. Templates are the ones startup validation
  // accepts — keep in sync with ScopedClientRegistrationFactoryTest#usableRedirectUris.

  @ParameterizedTest(name = "{0}")
  @MethodSource("redirectUrisAcceptedAtStartup")
  void callbackOfAnAcceptedRedirectUriIsMatchedByTheRedirectionEndpoint(final String redirectUri)
      throws URISyntaxException {
    for (final var contextPath : List.of("", SAMPLE_CONTEXT_PATH)) {
      // given the path Spring's resolver redirects the browser to, as the servlet reports it
      // (context-path stripped)
      final var callbackPath = contextRelativeCallbackPath(redirectUri, contextPath);

      // when the chain derives its redirection-endpoint path from the same redirect-uri
      final var endpointPath =
          OidcRedirectionEndpoint.resolve(redirectUri, contextPath, "/sso-callback");

      // then the redirection endpoint matches that callback (whether a chain is selected for the
      // request is the host's SecurityPathPort, not this value)
      final var request = new MockHttpServletRequest("GET", contextPath + callbackPath);
      request.setContextPath(contextPath);
      request.setServletPath(callbackPath);
      assertThat(PathPatternRequestMatcher.withDefaults().matcher(endpointPath).matches(request))
          .as(
              "redirect-uri '%s' under context-path '%s' expands to callback '%s', "
                  + "which must be matched by redirection endpoint '%s'",
              redirectUri, contextPath, callbackPath, endpointPath)
          .isTrue();
    }
  }

  private static Stream<String> redirectUrisAcceptedAtStartup() {
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
        "https://example.com{basePath}/orchestration/sso-callback");
  }

  /**
   * Expands {@code redirectUri} the way {@code DefaultOAuth2AuthorizationRequestResolver} does for
   * a deployment under {@code contextPath}, and returns the resulting path as the servlet reports
   * it to the matcher: without the context-path.
   */
  private static String contextRelativeCallbackPath(
      final String redirectUri, final String contextPath) throws URISyntaxException {
    final var baseUrl = "https://host:8443" + contextPath;
    final var expanded =
        new URI(
            UriComponentsBuilder.fromUriString(redirectUri)
                .buildAndExpand(
                    Map.of(
                        "baseUrl", baseUrl,
                        "baseScheme", "https",
                        "baseHost", "host",
                        "basePort", ":8443",
                        "basePath", contextPath,
                        "registrationId", "oidc",
                        "action", "login"))
                .toUriString());
    return OidcRedirectionEndpoint.stripContextPath(expanded.getPath(), contextPath);
  }
}
