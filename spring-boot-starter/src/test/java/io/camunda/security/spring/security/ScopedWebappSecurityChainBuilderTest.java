/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ScopedWebappSecurityChainBuilderTest {

  private static final String PRIMARY_AUTH_BASE_URI = "/oauth2/authorization";

  private static ClientRegistration registration(final String id) {
    return ClientRegistration.withRegistrationId(id)
        .clientId(id + "-client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/sso-callback")
        .authorizationUri("https://idp/authorize")
        .tokenUri("https://idp/token")
        .build();
  }

  @Test
  void singleRegistrationRedirectsStraightToProvider() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, LOGIN_URL))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  @Test
  void multipleRegistrationsRedirectToLoginPicker() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("a"), registration("b"));
    // Scoped login URL proves that loginUrl is threaded through rather than using the constant.
    final var scopedLoginUrl = "/physical-tenants/t1/login";
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, scopedLoginUrl))
        .isEqualTo(scopedLoginUrl);
  }

  @Test
  void nonIterableRepositoryFallsBackToDefaultRegistrationId() {
    final ClientRegistrationRepository repo = registrationId -> registration(registrationId);
    assertThat(ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(repo, LOGIN_URL))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  // Scoped chain: single-IdP redirect target must be prefixed with basePath

  /**
   * For a scoped chain with a single IdP, the redirect target must be {@code
   * <basePath>/oauth2/authorization/<id>} — not the unprefixed {@code /oauth2/authorization/<id>}.
   * Without threading {@code authorizationBaseUri}, the 302 would send the browser outside the
   * scope prefix, breaking scoped single-IdP login.
   */
  @Test
  void scopedSingleIdpRedirectTargetIsPrefixedWithBasePath() {
    final var basePath = "/physical-tenants/t1";
    final var authorizationBaseUri = basePath + "/oauth2/authorization";
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, basePath + LOGIN_URL, authorizationBaseUri))
        .isEqualTo(basePath + "/oauth2/authorization/oidc");
  }

  /**
   * For a scoped chain with a non-iterable repository (fallback case), the redirect target must
   * also be prefixed — {@code <basePath>/oauth2/authorization/oidc}.
   */
  @Test
  void scopedNonIterableRepositoryFallsBackToPrefixedDefaultRegistrationId() {
    final var basePath = "/physical-tenants/t1";
    final var authorizationBaseUri = basePath + "/oauth2/authorization";
    final ClientRegistrationRepository repo = registrationId -> registration(registrationId);
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, basePath + LOGIN_URL, authorizationBaseUri))
        .isEqualTo(basePath + "/oauth2/authorization/oidc");
  }

  /**
   * Confirms that the primary (non-scoped) single-IdP redirect target is unchanged — {@code
   * /oauth2/authorization/<id>} — so the fix is behaviour-neutral for primary chains.
   */
  @Test
  void primaryChainSingleIdpRedirectTargetIsUnchanged() {
    final ClientRegistrationRepository repo =
        new InMemoryClientRegistrationRepository(registration("oidc"));
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveOauthRedirectTarget(
                repo, LOGIN_URL, PRIMARY_AUTH_BASE_URI))
        .isEqualTo("/oauth2/authorization/oidc");
  }

  // post_logout_redirect_uri template: "{baseUrl}" + prefix + route

  /** Primary chain uses the empty prefix, so the route sits directly under {@code {baseUrl}}. */
  @Test
  void primaryPrefixProducesUnprefixedTemplate() {
    assertThat(
            ScopedWebappSecurityChainBuilder.postLogoutRedirectUri("", Optional.of("/post-logout")))
        .isEqualTo("{baseUrl}/post-logout");
  }

  /**
   * Scoped chain prepends its normalized base path (that {@code {baseUrl}} would otherwise drop),
   * so the redirect resolves under the scope. Also proves the single-slash join.
   */
  @Test
  void scopedPrefixIsPrependedToTemplate() {
    assertThat(
            ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
                "/physical-tenants/t1", Optional.of("/post-logout")))
        .isEqualTo("{baseUrl}/physical-tenants/t1/post-logout");
  }

  /** No route configured (the default): callers send no {@code post_logout_redirect_uri}. */
  @Test
  void absentRouteProducesEmptyTemplate() {
    assertThat(ScopedWebappSecurityChainBuilder.postLogoutRedirectUri("", Optional.empty()))
        .isEmpty();
  }

  /** A blank route is treated as absent. */
  @Test
  void blankRouteProducesEmptyTemplate() {
    assertThat(ScopedWebappSecurityChainBuilder.postLogoutRedirectUri("", Optional.of(" ")))
        .isEmpty();
  }

  /** A route without a leading slash is malformed for IdP allow-listing; fail fast at build. */
  @Test
  void routeWithoutLeadingSlashThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
                    "", Optional.of("post-logout")))
        .withMessageContaining("must start with '/'");
  }

  // redirection-endpoint path resolution (ADR-0038): configurable callback path

  @Test
  void redirectionEndpointPathDefaultsWhenRedirectUriUnset() {
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                null, "", "/sso-callback"))
        .isEqualTo("/sso-callback");
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "  ", "", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsBaseUrlPlaceholder() {
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "{baseUrl}/api/authentication/callback", "", "/sso-callback"))
        .isEqualTo("/api/authentication/callback");
  }

  @Test
  void redirectionEndpointPathStripsSchemeHostAndQuery() {
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "https://optimize.example.com/sso-callback?x=1", "", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathRewritesRegistrationIdPlaceholderToWildcard() {
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "{baseUrl}/login/oauth2/code/{registrationId}", "", "/sso-callback"))
        .isEqualTo("/login/oauth2/code/*");
  }

  @Test
  void redirectionEndpointPathRejectsResolvedPathWithoutLeadingSlash() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                    "{baseUrl}api/callback", "", "/sso-callback"))
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
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "https://host.example.com/orchestration/sso-callback",
                "/orchestration",
                "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void redirectionEndpointPathStripsContextPathOnlyOnWholeSegments() {
    // given a context-path that is a string prefix of a longer first segment
    // when resolved
    // then the partial match is not stripped
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
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
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
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
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "https://host.example.com/orchestration", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }
}
