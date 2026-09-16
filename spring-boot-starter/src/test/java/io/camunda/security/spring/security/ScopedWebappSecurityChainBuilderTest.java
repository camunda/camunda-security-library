/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.HEARTBEAT_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

class ScopedWebappSecurityChainBuilderTest {

  private static final String PRIMARY_AUTH_BASE_URI = "/oauth2/authorization";
  private static final String COMPOSED_DEFAULT = "{baseUrl}/post-logout";
  private static final String SCOPE_PREFIX = "/physical-tenants/t1";

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

  // configured post-logout-redirect-uri: per-registration override (ADR-0025)

  private static String resolvedPostLogoutRedirectUri(
      final String prefix, final OidcConfiguration.Builder oidc) {
    return ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
        "oidc", oidc.build(), prefix, COMPOSED_DEFAULT);
  }

  private static OidcConfiguration.Builder configuredUri(final String uri) {
    return OidcConfiguration.builder().postLogoutRedirectUri(uri);
  }

  /** Nothing configured: the host's composed route is used, exactly as before the property. */
  @Test
  void unsetConfiguredUriFallsBackToTheHostRoute() {
    assertThat(resolvedPostLogoutRedirectUri("", OidcConfiguration.builder()))
        .isEqualTo(COMPOSED_DEFAULT);
  }

  /** A blank value is treated as unset rather than as "send an empty parameter". */
  @Test
  void blankConfiguredUriFallsBackToTheHostRoute() {
    assertThat(resolvedPostLogoutRedirectUri("", configuredUri("  "))).isEqualTo(COMPOSED_DEFAULT);
  }

  /** A configured path overrides the host route but still resolves under the scope. */
  @Test
  void configuredPathIsComposedUnderTheScopePrefix() {
    assertThat(resolvedPostLogoutRedirectUri(SCOPE_PREFIX, configuredUri("/goodbye")))
        .isEqualTo("{baseUrl}" + SCOPE_PREFIX + "/goodbye");
  }

  /**
   * An absolute URL is passed through untouched — in particular it does <em>not</em> pick up the
   * scope prefix, which is the whole reason the property exists: the prefix is what makes the
   * composed URL impossible to register at an OP that matches the parameter exactly.
   */
  @Test
  void configuredAbsoluteUriIsReturnedVerbatimWithoutThePrefix() {
    assertThat(
            resolvedPostLogoutRedirectUri(
                SCOPE_PREFIX, configuredUri("https://accounts.example.com/logged-out")))
        .isEqualTo("https://accounts.example.com/logged-out");
  }

  /**
   * A template that expands to a relative value is rejected, even though every placeholder in it is
   * supported. RP-Initiated Logout requires {@code post_logout_redirect_uri} to be absolute, and
   * Spring expands this one to {@code /physical-tenants/t1/goodbye} — so without this check the IdP
   * rejects the logout at runtime rather than the deployment failing at startup.
   */
  @Test
  void configuredTemplateThatExpandsToARelativeValueThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("{basePath}/goodbye")))
        .withMessageContaining("must be an absolute URL");
  }

  /** Same for a placeholder that carries no scheme of its own. */
  @Test
  void configuredTemplateWithHostButNoSchemeThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("{baseHost}/logged-out")))
        .withMessageContaining("must be an absolute URL");
  }

  /** And for a supported placeholder that is not location-bearing at all. */
  @Test
  void configuredTemplateStartingWithANonLocationPlaceholderThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> resolvedPostLogoutRedirectUri("", configuredUri("{registrationId}/goodbye")))
        .withMessageContaining("must be an absolute URL");
  }

  /** A template spelling the scheme out explicitly still resolves absolute, so it is accepted. */
  @Test
  void configuredTemplateWithExplicitSchemeIsAccepted() {
    assertThat(
            resolvedPostLogoutRedirectUri(
                SCOPE_PREFIX, configuredUri("{baseScheme}://{baseHost}/logged-out")))
        .isEqualTo("{baseScheme}://{baseHost}/logged-out");
  }

  /**
   * A template is passed through too, so a host can opt out of the prefix while keeping baseUrl.
   */
  @Test
  void configuredTemplateIsReturnedVerbatimWithoutThePrefix() {
    assertThat(resolvedPostLogoutRedirectUri(SCOPE_PREFIX, configuredUri("{baseUrl}/post-logout")))
        .isEqualTo("{baseUrl}/post-logout");
  }

  /** Disabling the redirect beats a configured URI; the operator's kill switch is the stronger. */
  @Test
  void disabledRegistrationSendsNothingEvenWithAConfiguredUri() {
    assertThat(
            resolvedPostLogoutRedirectUri(
                "",
                configuredUri("https://accounts.example.com/logged-out")
                    .postLogoutRedirectEnabled(false)))
        .isEmpty();
  }

  /** A bare relative token is not a usable post_logout_redirect_uri at any OP; fail at startup. */
  @Test
  void schemelessRelativeConfiguredUriThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("goodbye")))
        .withMessageContaining("must be an absolute URL");
  }

  /**
   * Spring expands the template against a fixed six-variable map, so an unrecognised placeholder
   * throws from inside {@code buildAndExpand} on the logout request itself — a 500 on the one
   * request a user cannot usefully retry. Catch it at startup instead.
   */
  @Test
  void configuredUriWithUnsupportedTemplateVariableThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("{tenantId}/goodbye")))
        .withMessageContaining("unsupported template variable {tenantId}");
  }

  /**
   * An unclosed brace is the case a closed-pair check cannot see. {@code UriComponentsBuilder} does
   * not reject it either: <code>&#123;baseUrl&#125;&#123;tenantId</code> expands to the literal
   * <code>https://host&#123;tenantId</code>, verified empirically — so without this the malformed
   * URL reaches the IdP with no startup failure at all, the opposite of what this validation is
   * for.
   */
  @Test
  void configuredUriWithUnclosedBraceThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("{baseUrl}{tenantId")))
        .withMessageContaining("unclosed '{'");
  }

  /** A lone unclosed placeholder passes startsWith("{") but expands to itself; reject it too. */
  @Test
  void configuredUriThatIsOnlyAnUnclosedBraceThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("{baseUrl")))
        .withMessageContaining("unclosed '{'");
  }

  /** A stray closing brace is equally unexpandable. */
  @Test
  void configuredUriWithUnmatchedClosingBraceThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () -> resolvedPostLogoutRedirectUri("", configuredUri("https://x.example.com/a}")))
        .withMessageContaining("unmatched '}'");
  }

  /**
   * {@code "://"} is only a lexical hint. {@code "https://"} carries no authority at all, so it
   * fails to parse; without the parse step it would pass as "absolute" and be rejected by the OP at
   * logout instead of here.
   */
  @Test
  void configuredAbsoluteUriThatDoesNotParseThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("https://")))
        .withMessageContaining("is not a valid URI");
  }

  /** A URI that parses but names no host is equally unusable as a redirect target. */
  @Test
  void configuredAbsoluteUriWithoutHostThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> resolvedPostLogoutRedirectUri("", configuredUri("file:///logged-out")))
        .withMessageContaining("missing a scheme or a host");
  }

  /** An absolute URL whose host only exists after expansion must still be accepted. */
  @Test
  void configuredAbsoluteUriWithTemplateVariableHostIsAccepted() {
    assertThat(resolvedPostLogoutRedirectUri("", configuredUri("https://{baseHost}/logged-out")))
        .isEqualTo("https://{baseHost}/logged-out");
  }

  /**
   * A value is validated even when the redirect is switched off, so a typo surfaces at startup
   * rather than lying dormant until someone flips the flag back on.
   */
  @Test
  void configuredUriIsValidatedEvenWhenTheRedirectIsDisabled() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                resolvedPostLogoutRedirectUri(
                    "", configuredUri("{tenantId}/goodbye").postLogoutRedirectEnabled(false)))
        .withMessageContaining("unsupported template variable {tenantId}");
  }

  /** The value lands in a query parameter on a 302 Location header; CR/LF must not survive. */
  @Test
  void configuredUriWithCrlfThrows() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                resolvedPostLogoutRedirectUri(
                    "", configuredUri("https://accounts.example.com/x\r\nSet-Cookie: a=b")))
        .withMessageContaining("must not contain CR or LF");
  }

  // redirection-endpoint path resolution (ADR-0018): configurable callback path

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

  @Test
  void redirectionEndpointPathStripsContextPathWhenContextPathPropertyHasTrailingSlash() {
    // given the servlet context-path property itself carries a trailing slash (a value an operator
    // may set, e.g. server.servlet.context-path=/orchestration/) against a normal redirect-uri
    // when resolved
    // then stripContextPath normalizes the context-path and still yields the context-relative
    // callback
    assertThat(
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
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
            ScopedWebappSecurityChainBuilder.resolveRedirectionEndpointPath(
                "https://host.example.com/orchestration/", "/orchestration", "/sso-callback"))
        .isEqualTo("/sso-callback");
  }

  @Test
  void heartbeatMatcherIsAppendedToHostDeclaredPaths() {
    final var hostPaths = Set.of("/operate/**", "/tasklist/**");

    final var combined =
        ScopedWebappSecurityChainBuilder.withHeartbeatMatcher(hostPaths, HEARTBEAT_URL);

    assertThat(combined).contains("/operate/**", "/tasklist/**", HEARTBEAT_URL);
  }

  @Test
  void heartbeatMatcherIsPrefixedForScopedChains() {
    final var basePath = "/physical-tenants/t1";
    final var scopedHostPaths = List.of(basePath + "/operate/**");

    final var combined =
        ScopedWebappSecurityChainBuilder.withHeartbeatMatcher(
            scopedHostPaths, basePath + HEARTBEAT_URL);

    assertThat(combined).containsExactly(basePath + "/operate/**", basePath + "/session/heartbeat");
  }

  @Test
  void heartbeatMatcherIsIncludedEvenWhenHostDeclaresNoPaths() {
    final var combined =
        ScopedWebappSecurityChainBuilder.withHeartbeatMatcher(Set.of(), HEARTBEAT_URL);

    assertThat(combined).containsExactly(HEARTBEAT_URL);
  }
}
