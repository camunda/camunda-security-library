/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.spring.security.CamundaSecurityFilterChainConstants;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

/**
 * Builds {@link ClientRegistration} instances from {@link OidcConfiguration} maps. Extracted from
 * {@link OidcBeansConfiguration} so that the creation logic can be reused independently of the
 * Spring bean context. "Scoped" reflects that the factory builds registrations for an arbitrary
 * authentication scope (any per-scope security chain), not only the global configuration — future
 * per-scope chain building reuses this class without modification.
 *
 * <p><b>Discovery cache.</b> The first registration for an {@code issuer-uri} fetches that IdP's
 * discovery document over HTTP and the rest reuse it, so ten providers on one issuer cost one
 * fetch, not ten. A document is kept only if {@link ClientRegistrations#fromOidcConfiguration} can
 * read it back (see {@link #cacheDiscoveryDocument}); if it cannot, that issuer goes on fetching
 * once per registration.
 */
public final class ScopedClientRegistrationFactory {

  private static final Logger LOG = LoggerFactory.getLogger(ScopedClientRegistrationFactory.class);

  /**
   * Discovery documents already fetched, keyed by the raw {@code issuer-uri}. Never normalized:
   * {@code fromIssuerLocation} builds the well-known path from the exact string and checks the
   * document's own {@code issuer} against it, so trimming a trailing slash could serve one issuer's
   * document under another's key. Per instance, not static, and successes only — a failed fetch is
   * never cached.
   */
  private final Map<String, Map<String, Object>> discoveryByIssuer = new ConcurrentHashMap<>();

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map. The map key is used
   * as the {@code registrationId}.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers) {
    return createFromProviderMap(providers, null);
  }

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map, overriding the
   * {@code redirect_uri} for each registration when {@code scopedRedirectUriPath} is non-null and
   * non-blank.
   *
   * <p>The scoped webapp chain's redirection endpoint listens at a prefixed path (e.g. {@code
   * /physical-tenants/{id}/sso-callback}). The registrations built here must carry a matching
   * {@code redirect_uri} so that {@code DefaultOAuth2AuthorizationRequestResolver} sends the
   * correct callback URL to the IdP. Without this override the IdP calls back to the unprefixed
   * cluster path, which the scoped chain never intercepts.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @param scopedRedirectUriPath path component to use as the redirect-uri (e.g. {@code
   *     /physical-tenants/t1/sso-callback}); when {@code null} or blank the redirect-uri from the
   *     {@link OidcConfiguration} is used unchanged
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank but does not start with
   *     '/'
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    Objects.requireNonNull(providers, "providers must not be null");
    // A non-blank path without a leading '/' would produce "{baseUrl}physical-tenants/..." which is
    // not a valid URI — reject it early so the caller gets a clear error instead of a subtle
    // misuse.
    if (StringUtils.hasText(scopedRedirectUriPath) && !scopedRedirectUriPath.startsWith("/")) {
      throw new IllegalArgumentException(
          "scopedRedirectUriPath must start with '/', but was: " + scopedRedirectUriPath);
    }
    return providers.entrySet().stream()
        .map(e -> buildClientRegistration(e.getKey(), e.getValue(), scopedRedirectUriPath))
        .toList();
  }

  /**
   * Flattens an {@link AuthenticationConfiguration} into a provider map keyed by registrationId.
   * The flat {@code oidc.*} block contributes one entry under its {@link
   * OidcConfiguration#getRegistrationId()} when {@code clientId} is set; provider entries from
   * {@code providers.oidc.*} are put on top, so a colliding provider id overwrites the flat entry.
   * This is the single authoritative implementation of the merge rule; {@link
   * OidcAuthenticationConfigurationRepository#initializeProviders} delegates here.
   *
   * @param authentication the authentication configuration to flatten; must not be {@code null}
   * @return a {@link LinkedHashMap} keyed by registrationId; never {@code null}
   */
  public Map<String, OidcConfiguration> flatten(final AuthenticationConfiguration authentication) {
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var flat = authentication.getOidc();
    final Map<String, OidcConfiguration> result = new LinkedHashMap<>();
    if (StringUtils.hasText(flat.getClientId())) {
      result.put(flat.getRegistrationId(), flat);
    }
    result.putAll(authentication.getProviders().getOidc());
    return result;
  }

  /**
   * Convenience method: flattens the {@link AuthenticationConfiguration} and builds all {@link
   * ClientRegistration} instances from the result.
   *
   * @param authentication the authentication configuration; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances
   * @throws IllegalStateException if any registrationId is blank or a configuration lacks required
   *     endpoint information
   */
  public List<ClientRegistration> create(final AuthenticationConfiguration authentication) {
    return createFromProviderMap(flatten(authentication));
  }

  /**
   * Builds a single {@link ClientRegistration} from {@link OidcConfiguration}. When {@code
   * issuer-uri} is set, OIDC discovery populates the authorization/token/user-info/jwk-set URIs
   * automatically; any explicitly-configured endpoint URI on {@link OidcConfiguration} then
   * overrides the discovered value. When {@code issuer-uri} is unset, all of authorization-uri,
   * token-uri, and jwk-set-uri must be configured explicitly. The {@code registrationId} argument
   * is the map key in the multi-provider shape and {@link OidcConfiguration#getRegistrationId()} in
   * the legacy flat shape.
   *
   * <p>The redirect-uri is resolved by {@link #resolveRedirectUri}: a scoped path wins, then an
   * explicitly-configured {@code redirect-uri}, then the {@code {baseUrl}/sso-callback} default.
   * Spring expands the {@code {baseUrl}} placeholder to the application's base URL — {@code
   * scheme://host:port} plus the servlet context path, if any — at request time.
   */
  private ClientRegistration buildClientRegistration(
      final String registrationId,
      final OidcConfiguration oidc,
      final String scopedRedirectUriPath) {
    if (!StringUtils.hasText(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId must be non-blank: set"
              + " camunda.security.authentication.oidc.registration-id (flat block)"
              + " or use a non-blank key under"
              + " camunda.security.authentication.providers.oidc.<id>.*");
    }
    final var redirectUri = resolveRedirectUri(oidc, scopedRedirectUriPath);
    final ClientRegistration.Builder builder =
        clientRegistrationBuilder(registrationId, oidc)
            .registrationId(registrationId)
            .clientId(oidc.getClientId())
            .clientSecret(oidc.getClientSecret())
            .clientAuthenticationMethod(
                new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod()))
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .scope(oidc.getScope());
    if (StringUtils.hasText(oidc.getClientName())) {
      builder.clientName(oidc.getClientName());
    }
    if (!oidc.isUserInfoEnabled()) {
      builder.userInfoUri(null);
    }
    final var built = builder.build();
    if (StringUtils.hasText(oidc.getIssuerUri())) {
      cacheDiscoveryDocument(oidc.getIssuerUri(), built);
    }
    return mergeProviderMetadata(built, oidc);
  }

  /**
   * Stores the issuer's discovery document, but only if {@link
   * ClientRegistrations#fromOidcConfiguration} can turn it back into a builder. The document is
   * taken from the finished registration, so the first fetch behaves exactly as before, and the
   * explicit endpoint overrides change builder fields rather than the document itself.
   *
   * <p>The check is needed because Spring looks for the document in more than one place. When it
   * falls back to the RFC 8414 location it accepts a document that can leave out {@code jwks_uri}
   * and other fields {@code fromOidcConfiguration} requires; storing one of those would let the
   * first registration succeed and break every later one. Checking on the way in means everything
   * in the cache can be used, and an issuer that fails the check simply fetches once per
   * registration, as it did before.
   */
  private void cacheDiscoveryDocument(final String issuerUri, final ClientRegistration built) {
    if (discoveryByIssuer.containsKey(issuerUri)) {
      return;
    }
    final Map<String, Object> document =
        new LinkedHashMap<>(built.getProviderDetails().getConfigurationMetadata());
    try {
      ClientRegistrations.fromOidcConfiguration(document);
    } catch (final RuntimeException notReConsumable) {
      LOG.debug(
          "Not caching the discovery document for issuer {}: it cannot be read back into a builder"
              + " ({}). This issuer keeps resolving once per client registration.",
          issuerUri,
          notReConsumable.getMessage());
      return;
    }
    discoveryByIssuer.putIfAbsent(issuerUri, document);
  }

  /**
   * Adds this registration's own entries to the discovered metadata by build-then-rebuild, since
   * {@code providerConfigurationMetadata} replaces the map and would drop a discovered {@code
   * end_session_endpoint}. The audiences key is always set, even when empty, because it is
   * authoritative by presence; an explicit end-session endpoint wins.
   *
   * <p>The map is fresh per registration — the only reason registrations sharing an issuer cannot
   * see each other's audiences.
   */
  private static ClientRegistration mergeProviderMetadata(
      final ClientRegistration built, final OidcConfiguration oidc) {
    final Map<String, Object> merged =
        new LinkedHashMap<>(built.getProviderDetails().getConfigurationMetadata());
    merged.put(
        TokenValidatorFactory.AUDIENCES_METADATA_KEY,
        oidc.getAudiences() != null ? List.copyOf(oidc.getAudiences()) : List.of());
    if (StringUtils.hasText(oidc.getEndSessionEndpointUri())) {
      merged.put("end_session_endpoint", oidc.getEndSessionEndpointUri());
    }
    return ClientRegistration.withClientRegistration(built)
        .providerConfigurationMetadata(merged)
        .build();
  }

  /**
   * Resolves the {@code redirect_uri} for a registration, in precedence order:
   *
   * <ol>
   *   <li>a scoped path (per-scope chain) as {@code {baseUrl}<scopedRedirectUriPath>}, so the
   *       callback matches the prefixed redirection endpoint of that chain;
   *   <li>an explicitly-configured {@code redirect-uri} on the {@link OidcConfiguration}, which
   *       must start with {@code {baseUrl}} or be an absolute {@code scheme://host} URL (a bare
   *       path is rejected — see {@link OidcConfiguration#getRedirectUri()});
   *   <li>the {@code {baseUrl}/sso-callback} default, matching the redirection endpoint registered
   *       under {@link CamundaSecurityFilterChainConstants#REDIRECT_URI}.
   * </ol>
   *
   * <p>The default lets a provider that omits {@code redirect-uri} still complete the login flow,
   * matching the behaviour of OC's former {@code ClientRegistrationFactory}.
   *
   * @throws IllegalArgumentException if the configured {@code redirect-uri} is a bare path (no
   *     {@code {baseUrl}} template and no {@code scheme://host}); it would derive a working local
   *     filter path but send a non-absolute {@code redirect_uri} to the IdP, breaking login.
   */
  private static String resolveRedirectUri(
      final OidcConfiguration oidc, final String scopedRedirectUriPath) {
    if (StringUtils.hasText(scopedRedirectUriPath)) {
      return "{baseUrl}" + scopedRedirectUriPath;
    }
    if (StringUtils.hasText(oidc.getRedirectUri())) {
      final String configured = oidc.getRedirectUri();
      if (!configured.startsWith("{baseUrl}") && !configured.contains("://")) {
        throw new IllegalArgumentException(
            "camunda.security.authentication.oidc.redirect-uri must start with '{baseUrl}' or be an"
                + " absolute 'scheme://host' URL so the redirect_uri sent to the IdP is absolute,"
                + " but was: "
                + configured);
      }
      return configured;
    }
    return "{baseUrl}" + CamundaSecurityFilterChainConstants.REDIRECT_URI;
  }

  /**
   * Builds the base {@link ClientRegistration.Builder}: discovery via {@code issuer-uri} when set,
   * otherwise an empty builder; in both cases any explicitly-configured endpoint URI on {@link
   * OidcConfiguration} overrides the discovered value. A non-blank value on the configuration
   * always wins; a null/blank value leaves the discovered value untouched.
   *
   * <p>Mirrors OC's previous {@code ClientRegistrationFactory} so that adopters can rely on
   * explicit overrides to plug gaps in incomplete IdP discovery metadata (older Keycloak realms,
   * custom STS endpoints, proxies that rewrite discovery documents). See
   * camunda/camunda-security-library#233.
   */
  private ClientRegistration.Builder clientRegistrationBuilder(
      final String registrationId, final OidcConfiguration oidc) {
    final boolean hasIssuer = StringUtils.hasText(oidc.getIssuerUri());
    final ClientRegistration.Builder builder =
        hasIssuer
            ? discoveredBuilder(oidc.getIssuerUri()).registrationId(registrationId)
            : ClientRegistration.withRegistrationId(registrationId);

    if (!hasIssuer
        && (!StringUtils.hasText(oidc.getAuthorizationUri())
            || !StringUtils.hasText(oidc.getTokenUri())
            || !StringUtils.hasText(oidc.getJwkSetUri()))) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
              + " under camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*");
    }

    return applyExplicitEndpointOverrides(builder, oidc);
  }

  /**
   * A builder filled in from the issuer's discovery document, rebuilt from the cached copy when we
   * already have one.
   *
   * <p>{@code get} then {@code putIfAbsent}, not {@code computeIfAbsent}: the latter locks part of
   * the map while a 30-second HTTP call runs, which blocks threads looking up other issuers. The
   * worst a race costs here is one extra fetch.
   *
   * <p>Cache the document, not a builder and not a finished registration. Two registrations that
   * shared a builder would also share the fields set only when configured, so one provider's
   * explicit {@code jwk-set-uri} would become the other's. Sharing a finished registration would
   * also share client credentials, scopes and audiences — and a registration's audiences count as
   * set simply by being present under {@link TokenValidatorFactory#AUDIENCES_METADATA_KEY}, so one
   * scope's tokens would pass another scope's checks. Audiences stay separate only because {@link
   * #mergeProviderMetadata} builds a new map for each registration.
   */
  private ClientRegistration.Builder discoveredBuilder(final String issuerUri) {
    final var cached = discoveryByIssuer.get(issuerUri);
    return cached != null
        ? ClientRegistrations.fromOidcConfiguration(cached)
        : ClientRegistrations.fromIssuerLocation(issuerUri);
  }

  /**
   * Applies any explicitly-configured endpoint URI on top of the builder, so a non-blank value on
   * the configuration always wins and a null/blank one leaves the discovered value untouched.
   *
   * <p>Must run before the registration is built: on the {@code issuer-uri} path these overrides
   * are what plug gaps in an incomplete discovery document, and {@code build()} asserts that {@code
   * authorizationUri} and {@code tokenUri} are present.
   */
  private static ClientRegistration.Builder applyExplicitEndpointOverrides(
      final ClientRegistration.Builder builder, final OidcConfiguration oidc) {
    if (StringUtils.hasText(oidc.getAuthorizationUri())) {
      builder.authorizationUri(oidc.getAuthorizationUri());
    }
    if (StringUtils.hasText(oidc.getTokenUri())) {
      builder.tokenUri(oidc.getTokenUri());
    }
    if (StringUtils.hasText(oidc.getJwkSetUri())) {
      builder.jwkSetUri(oidc.getJwkSetUri());
    }
    if (StringUtils.hasText(oidc.getUserInfoUri())) {
      builder.userInfoUri(oidc.getUserInfoUri());
    }
    return builder;
  }
}
