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
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import java.util.List;
import java.util.Map;
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

  // configured post-logout-redirect-uri: composition (ADR-0026)
  //
  // Only the resolution of an already-valid value lives here. Rejecting a malformed one is
  // ScopedClientRegistrationFactory's job now, and ScopedClientRegistrationFactoryTest covers it.

  private static String resolvedPostLogoutRedirectUri(
      final String prefix, final OidcConfiguration.Builder oidc) {
    return ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
        "oidc", oidc.build(), prefix, COMPOSED_DEFAULT, true);
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

  /**
   * A value {@link ScopedClientRegistrationFactory} warned about (unusable, not merely unset) falls
   * back the same way, instead of reaching {@code buildAndExpand} at logout — where an unclosed
   * brace or a CR/LF would throw and fail the request, rather than just warn.
   */
  @Test
  void unusableConfiguredUriFallsBackToTheHostRoute() {
    assertThat(
            ScopedWebappSecurityChainBuilder.postLogoutRedirectUri(
                "oidc",
                configuredUri("{baseUrl}/post-logout{tenantId").build(),
                "",
                COMPOSED_DEFAULT,
                false))
        .isEqualTo(COMPOSED_DEFAULT);
  }

  /**
   * Covers the seam {@code unusableConfiguredUriFallsBackToTheHostRoute} above does not: that one
   * passes {@code usable=false} in by hand, so it proves only that {@code postLogoutRedirectUri}
   * honours the flag. This exercises the real wiring — {@code isPostLogoutRedirectUriUsable}
   * actually returning false for an unusable value, and {@code postLogoutRedirectUris} passing that
   * verdict through — using a real {@link ScopedClientRegistrationFactory}, not a mock.
   */
  @Test
  void postLogoutRedirectUrisFallsBackForARegistrationWithAnUnusableConfiguredUri() {
    final var factory = new ScopedClientRegistrationFactory();
    final var oidc =
        OidcConfiguration.builder()
            .clientId("client")
            .issuerUri("https://idp.example.com/realms/camunda")
            .postLogoutRedirectUri("{baseUrl}/post-logout{tenantId")
            .build();

    final var redirectUris =
        ScopedWebappSecurityChainBuilder.postLogoutRedirectUris(
            factory, Map.of("oidc", oidc), "", COMPOSED_DEFAULT);

    assertThat(redirectUris).containsEntry("oidc", COMPOSED_DEFAULT);
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
