/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcProvidersConfiguration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Authentication configuration bound to {@code camunda.security.authentication.*}.
 *
 * <p>This model is consumed by host applications through CSL's Spring binding and represents the
 * top-level authentication behavior switches (method selection, dev-mode API exposure, refresh
 * interval, and OIDC sub-configuration).
 */
public class AuthenticationConfiguration {

  /** Default authentication method when no explicit value is configured. */
  public static final AuthenticationMethod DEFAULT_METHOD = AuthenticationMethod.BASIC;

  /** Default for {@code camunda.security.authentication.unprotected-api}. */
  public static final boolean DEFAULT_UNPROTECTED_API = false;

  /** Default for {@code camunda.security.authentication.webapp-enabled}. */
  public static final boolean DEFAULT_WEBAPP_ENABLED = true;

  /** Default for {@code camunda.security.authentication.catch-all-unhandled-paths-enabled}. */
  public static final boolean DEFAULT_CATCH_ALL_UNHANDLED_PATHS_ENABLED = true;

  /** Authentication method. Either {@code basic} or {@code oidc}. Defaults to {@code basic}. */
  private AuthenticationMethod method = DEFAULT_METHOD;

  /**
   * When {@code true}, the API is unprotected (development mode only). Setting this disables the
   * OIDC and basic auth API protection chains in favour of a permit-all chain.
   */
  private boolean unprotectedApi = DEFAULT_UNPROTECTED_API;

  /**
   * When {@code false}, the webapp UI chain ({@code OidcWebappSecurityConfiguration} or {@code
   * BasicAuthWebappSecurityConfiguration}, depending on {@link #method}) is not activated, leaving
   * only the API-protection chain active. Defaults to {@code true} (webapp chain active, matching
   * behavior before this property existed).
   *
   * <p>Bound as {@code camunda.security.authentication.webapp-enabled} — a flat boolean, matching
   * the sibling {@link #unprotectedApi} property, rather than the nested {@code webapp.enabled}
   * shape originally proposed in camunda-security-library#548.
   */
  private boolean webappEnabled = DEFAULT_WEBAPP_ENABLED;

  /**
   * When {@code true} (default), the always-on catch-all deny chain ({@code
   * protectedUnhandledPathsSecurityFilterChain}) is registered so any path not claimed by another
   * chain is denied. A host whose own webapp chain already uses a {@code /**} catch-all matcher
   * (e.g. Optimize) sets this to {@code false} so the two {@code /**} chains do not collide at
   * startup. Disabling it without another catch-all chain leaves unhandled paths unsecured.
   */
  private boolean catchAllUnhandledPathsEnabled = DEFAULT_CATCH_ALL_UNHANDLED_PATHS_ENABLED;

  /**
   * Authentication refresh interval in ISO-8601 duration format (for example {@code PT30S}).
   *
   * <p>Used by holders that cache authentication state (for example session-based holders) to
   * decide when the cached value should be refreshed.
   */
  private String authenticationRefreshInterval = "PT30S";

  /** OIDC-specific settings (only consulted when {@code method == OIDC}). */
  private OidcConfiguration oidc = new OidcConfiguration();

  private OidcProvidersConfiguration providers = new OidcProvidersConfiguration();

  public AuthenticationMethod getMethod() {
    return method;
  }

  public void setMethod(final AuthenticationMethod method) {
    this.method = method;
  }

  public boolean isUnprotectedApi() {
    return unprotectedApi;
  }

  public void setUnprotectedApi(final boolean unprotectedApi) {
    this.unprotectedApi = unprotectedApi;
  }

  public boolean isWebappEnabled() {
    return webappEnabled;
  }

  public void setWebappEnabled(final boolean webappEnabled) {
    this.webappEnabled = webappEnabled;
  }

  public boolean isCatchAllUnhandledPathsEnabled() {
    return catchAllUnhandledPathsEnabled;
  }

  public void setCatchAllUnhandledPathsEnabled(final boolean catchAllUnhandledPathsEnabled) {
    this.catchAllUnhandledPathsEnabled = catchAllUnhandledPathsEnabled;
  }

  public String getAuthenticationRefreshInterval() {
    return authenticationRefreshInterval;
  }

  public void setAuthenticationRefreshInterval(final String authenticationRefreshInterval) {
    this.authenticationRefreshInterval = authenticationRefreshInterval;
  }

  public OidcConfiguration getOidc() {
    return oidc;
  }

  public void setOidc(final OidcConfiguration oidc) {
    this.oidc = oidc != null ? oidc : new OidcConfiguration();
  }

  public OidcProvidersConfiguration getProviders() {
    return providers;
  }

  public void setProviders(final OidcProvidersConfiguration providers) {
    this.providers = providers != null ? providers : new OidcProvidersConfiguration();
  }

  /**
   * Whether some users get their groups from Camunda: the method is not OIDC, or an OIDC provider
   * has no groups claim. A host shows Camunda's group management when this is {@code true}.
   *
   * <p>A provider without its own {@code groups-claim} uses the one of the {@code oidc} block. With
   * a single provider this is always the opposite of {@link #isExternalGroupsEnabled()}; with
   * several, both can be {@code true}.
   */
  public boolean isCamundaGroupsEnabled() {
    return getMethod() != AuthenticationMethod.OIDC
        || oidcProviders().stream().anyMatch(provider -> groupsClaimOf(provider) == null);
  }

  /**
   * Whether some users get their groups from a groups claim of their OIDC provider. Camunda does
   * not know those groups, so a host must not require a group it is given to exist in Camunda when
   * this is {@code true}.
   *
   * <p>A provider without its own {@code groups-claim} uses the one of the {@code oidc} block.
   */
  public boolean isExternalGroupsEnabled() {
    return getMethod() == AuthenticationMethod.OIDC
        && oidcProviders().stream().anyMatch(provider -> groupsClaimOf(provider) != null);
  }

  /**
   * The groups claim to read the groups of a token of {@code issuer} from: the one of the first
   * provider with that {@code issuer-uri}, the {@code oidc} block first. Issuer-uris that differ
   * only by a trailing slash are one issuer, because discovery settles both on the provider's
   * issuer. That is the provider that verifies the token. A provider without its own {@code
   * groups-claim}, and a token of no known issuer, use the one of the {@code oidc} block.
   *
   * @param issuer the {@code iss} claim of the token, or {@code null}
   * @return the groups claim, or {@code null} when the groups of the token's user come from Camunda
   */
  public String getGroupsClaim(final String issuer) {
    if (getMethod() != AuthenticationMethod.OIDC) {
      return null;
    }
    return oidcProviders().stream()
        .filter(provider -> isSameIssuer(issuer, provider.getIssuerUri()))
        .findFirst()
        .map(this::groupsClaimOf)
        .orElseGet(() -> groupsClaimOf(getOidc()));
  }

  /**
   * The OIDC providers, in the order of the configuration: the {@code oidc} block when it has a
   * {@code client-id}, then the named providers. A named provider with the registration ID of the
   * {@code oidc} block replaces it, as the client registrations do. A provider with a blank
   * registration ID is left out, as the token decoders leave it out. Without any provider, the
   * {@code oidc} block alone, so its {@code groups-claim} still decides.
   */
  private List<OidcConfiguration> oidcProviders() {
    final Map<String, OidcConfiguration> byRegistrationId = new LinkedHashMap<>();
    if (hasText(getOidc().getClientId())) {
      byRegistrationId.put(getOidc().getRegistrationId(), getOidc());
    }
    getProviders()
        .getOidc()
        .forEach(
            (registrationId, provider) -> {
              if (provider != null) {
                byRegistrationId.put(registrationId, provider);
              }
            });
    byRegistrationId.keySet().removeIf(registrationId -> !hasText(registrationId));
    return byRegistrationId.isEmpty() ? List.of(getOidc()) : List.copyOf(byRegistrationId.values());
  }

  private String groupsClaimOf(final OidcConfiguration provider) {
    if (provider.isGroupsClaimConfigured()) {
      return provider.getGroupsClaim();
    }
    return getOidc().isGroupsClaimConfigured() ? getOidc().getGroupsClaim() : null;
  }

  private static boolean hasText(final String value) {
    return value != null && !value.isBlank();
  }

  private static boolean isSameIssuer(final String issuer, final String issuerUri) {
    return hasText(issuer)
        && hasText(issuerUri)
        && withoutTrailingSlash(issuer).equals(withoutTrailingSlash(issuerUri));
  }

  private static String withoutTrailingSlash(final String issuer) {
    return issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
  }

  /** Camunda-managed users are disabled when OIDC authentication is active. */
  public boolean isCamundaUsersEnabled() {
    return getMethod() != AuthenticationMethod.OIDC;
  }
}
