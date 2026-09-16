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
    // the absolute URL the chart renders for a context-path'd webapp spells the context path out
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsASegmentTheContextPathPlaceholderAlreadyAccountsFor() {
    // {baseUrl} stands for the context path already, so the repeated segment belongs to the
    // callback; taking it off would mount the endpoint a segment above where the browser lands
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "{baseUrl}/orchestration/sso-callback", "/orchestration", "/sso-callback"))
        .isEqualTo("/orchestration/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsASegmentTheBasePathPlaceholderAlreadyAccountsFor() {
    // the same shape spelled out with {basePath}, which expands from the context path too
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com{basePath}/orchestration/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/orchestration/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsContextPathOnlyOnWholeSegments() {
    // a context path that is a string prefix of a longer first segment is not stripped
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration-ui/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/orchestration-ui/sso-callback");
  }

  @Test
  void redirectionEndpointPathKeepsPathWhenContextPathNotEmbedded() {
    // nothing to strip: a root-registered callback (Optimize CCSaaS) does not spell the context
    // path out, and the servlet takes it off the request anyway
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/sso-callback?uuid=cluster-1",
                "/cluster-1",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriIsExactlyContextPath() {
    // no callback segment left, so the default stands in rather than a blank matcher
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsContextPathWhenContextPathPropertyHasTrailingSlash() {
    // a context-path property an operator wrote with a trailing slash is normalized first
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/sso-callback",
                "/orchestration/",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriIsContextPathWithTrailingSlash() {
    // the context root with a trailing slash falls back too, not to a "/" matcher no callback hits
    assertThat(
            OidcRedirectionEndpoint.resolve(
                "https://host.example.com/orchestration/", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  // Both sides are derived from the real components, so a redirect-uri shape one supports and the
  // other does not fails here rather than at login.

  @ParameterizedTest(name = "{0}")
  @MethodSource("io.camunda.security.spring.oidc.RedirectUriSamples#usable")
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
