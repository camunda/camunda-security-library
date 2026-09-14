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
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.PathContainer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.pattern.PathPatternParser;
import org.springframework.web.util.pattern.PatternParseException;

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

  private static final String BASE_URL_PLACEHOLDER = "{baseUrl}";

  /** Mirrors the login route {@code LoginLinksBuilder} emits, for id addressability checks. */
  private static final String LOGIN_ROUTE_PROBE = "https://probe.invalid/oauth2/authorization/";

  /**
   * Whether a request for this callback can reach a filter chain at all. Spring Security's default
   * {@code StrictHttpFirewall} blocklists these substrings in a request URL and rejects the request
   * before any chain is consulted, so a redirect-uri expanding to such a path names a callback the
   * IdP would send the browser to and nothing could answer. The list is pinned against the firewall
   * itself in {@code ScopedClientRegistrationFactoryTest}.
   */
  private static final List<String> REJECTED_BY_THE_DEFAULT_FIREWALL =
      List.of("//", ";", "%3b", "%2f", "\\", "%5c", "%25", "%2e", "%00", "%0a", "%0d");

  /**
   * Segments the same firewall rejects as a non-normalized request URL, so a callback carrying one
   * is unreachable for the same reason.
   */
  private static final List<String> DOT_SEGMENTS = List.of(".", "..");

  /**
   * Discovery documents already fetched, keyed by the raw {@code issuer-uri}. Never normalized:
   * {@code fromIssuerLocation} builds the well-known path from the exact string and checks the
   * document's own {@code issuer} against it, so trimming a trailing slash could serve one issuer's
   * document under another's key. Per instance, not static, and successes only — a failed fetch is
   * never cached.
   */
  private final Map<String, Map<String, Object>> discoveryByIssuer = new ConcurrentHashMap<>();

  /** The deployment's context path as {@code request.getContextPath()} reports it. */
  private final String basePath;

  /** Validates redirect-uri templates against a deployment without a servlet context path. */
  public ScopedClientRegistrationFactory() {
    this("");
  }

  /**
   * @param servletContextPath {@code server.servlet.context-path} as configured, {@code ""} when
   *     unset — the same raw value {@link OidcRedirectionEndpoint#resolve} resolves a redirection
   *     endpoint against, so both sides judge a redirect-uri under the deployment's real context
   *     path
   */
  public ScopedClientRegistrationFactory(final String servletContextPath) {
    basePath = contextPathAsTheServletReportsIt(servletContextPath);
  }

  /**
   * Stand-ins for the request-derived values {@code DefaultOAuth2AuthorizationRequestResolver}
   * expands a redirect-uri against, both carrying the deployment's own context path and the
   * registration's own id, and differing in the port: {@code basePort} expands with its own {@code
   * :} only on a non-default port, so a template that supplies the {@code :} itself is absolute on
   * the first shape and broken on the second.
   */
  private List<Map<String, String>> sampleRequestShapes(final String registrationId) {
    return List.of(
        sampleRequestShape("", registrationId), sampleRequestShape(":8443", registrationId));
  }

  private Map<String, String> sampleRequestShape(
      final String basePort, final String registrationId) {
    return Map.of(
        "baseUrl",
        "https://host" + basePort + basePath,
        "baseScheme",
        "https",
        "baseHost",
        "host",
        "basePort",
        basePort,
        "basePath",
        basePath,
        "registrationId",
        registrationId,
        "action",
        "login");
  }

  /**
   * Normalizes a configured {@code server.servlet.context-path} to what {@code
   * request.getContextPath()} reports, which is what the resolver expands {@code basePath} from:
   * {@code ""} for a root deployment, otherwise a leading and no trailing slash. A configured
   * {@code /orchestration/} would otherwise expand to a callback with an empty path segment that no
   * request can carry.
   */
  private static String contextPathAsTheServletReportsIt(final String configured) {
    if (!StringUtils.hasText(configured) || "/".equals(configured)) {
      return "";
    }
    final var withLeadingSlash = configured.startsWith("/") ? configured : "/" + configured;
    return withLeadingSlash.endsWith("/")
        ? withLeadingSlash.substring(0, withLeadingSlash.length() - 1)
        : withLeadingSlash;
  }

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map. The map key is used
   * as the {@code registrationId}.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes
   * @throws IllegalArgumentException if a configured redirect-uri does not expand to a usable
   *     callback URL
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers) {
    return createFromProviderMap(providers, null);
  }

  /**
   * Creates one {@link ClientRegistration} per entry in the given provider map, overriding the
   * {@code redirect_uri} for each registration when {@code scopedRedirectUriPath} is non-null and
   * non-blank. The whole map is validated with {@link #validateWithoutNetwork} first, so a
   * malformed entry is reported before an earlier entry's issuer is contacted for discovery.
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
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank but is not a path the
   *     default firewall lets through, or a configured redirect-uri does not expand to a usable
   *     callback URL
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes
   * @throws IllegalArgumentException if a configured redirect-uri does not expand to a usable
   *     callback URL
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    return createFromProviderMap(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  /**
   * Creates one {@link ClientRegistration} per entry for a caller that derives no browser login
   * route from the configuration — an API chain's token validation, or UserInfo augmentation, both
   * of which read the issuer, keys and endpoints of a registration and never redirect a browser.
   *
   * <p>Every check on a value such a caller uses still runs. The {@link LoginRouteChecks login
   * route checks} do not: a redirect-uri this application could not serve, or a registration id the
   * login route could not address, is not a reason to refuse to start where no login route exists.
   * The login paths — the webapp client beans and the webapp chains — still reject both, which is
   * where either is what actually breaks.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes, other than the login route checks
   */
  public List<ClientRegistration> createWithoutLoginRoutes(
      final Map<String, OidcConfiguration> providers) {
    return createFromProviderMap(providers, null, LoginRouteChecks.SKIPPED);
  }

  /**
   * As {@link #createWithoutLoginRoutes(Map)}, flattening the {@link AuthenticationConfiguration}
   * first.
   *
   * @param authentication the authentication configuration; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes, other than the login route checks
   */
  public List<ClientRegistration> createWithoutLoginRoutes(
      final AuthenticationConfiguration authentication) {
    return createWithoutLoginRoutes(flatten(authentication));
  }

  private List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
    validateWithoutNetwork(providers, scopedRedirectUriPath, loginRouteChecks);
    return providers.entrySet().stream()
        .map(
            e ->
                buildClientRegistration(
                    e.getKey(), e.getValue(), scopedRedirectUriPath, loginRouteChecks))
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
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes
   */
  public List<ClientRegistration> create(final AuthenticationConfiguration authentication) {
    return createFromProviderMap(flatten(authentication));
  }

  /**
   * Runs every check {@link #createFromProviderMap(Map, String)} performs that needs no network
   * access, without building any registration. Lets a caller that resolves registrations lazily
   * still reject a malformed provider block at startup, where the misconfiguration belongs, rather
   * than on the first request that happens to need it.
   *
   * @throws IllegalStateException if a registrationId, client-id or client-authentication-method is
   *     blank, a registrationId is not addressable as a single path segment of the login route, a
   *     scope carries a character a scope token cannot, a provider sets neither issuer-uri nor all
   *     of authorization-uri, token-uri and jwk-set-uri, or a configured endpoint URL is not an
   *     absolute http(s) URL with a host and a port in TCP range. The URL checks run before the
   *     completeness check, so a malformed value in an otherwise incomplete block is named rather
   *     than hidden behind the completeness error.
   * @throws IllegalArgumentException if {@code scopedRedirectUriPath} is not absolute or is a path
   *     the default firewall blocks, or a configured redirect-uri does not expand to a usable
   *     callback URL
   */
  public void validateWithoutNetwork(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    validateWithoutNetwork(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  private void validateWithoutNetwork(
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
    Objects.requireNonNull(providers, "providers must not be null");
    requireAbsoluteScopedRedirectUriPath(scopedRedirectUriPath);
    providers.forEach(
        (registrationId, oidc) -> {
          requireRegistrationId(registrationId);
          if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
            requireRegistrationIdAddressableByTheLoginRoute(registrationId);
          }
          requireClientId(registrationId, oidc);
          requireClientAuthenticationMethod(registrationId, oidc);
          requireUsableScopes(registrationId, oidc);
          requireAbsoluteEndpointUrls(registrationId, oidc);
          requireEndpointConfiguration(registrationId, oidc);
          resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks);
        });
  }

  /**
   * Whether the caller derives browser login routes from the configuration — the login route from
   * the registration id and the redirection endpoint from the redirect-uri. A caller that derives
   * neither is held to neither.
   */
  private enum LoginRouteChecks {
    ENFORCED,
    SKIPPED
  }

  /**
   * Validates the flat {@code redirect-uri} the unscoped webapp chain mounts its redirection
   * endpoint from, against the same contract a provider's value is held to. The flat block drives
   * that endpoint whether or not it also contributes a registration, so a value set without a
   * {@code client-id} never reaches {@link #validateWithoutNetwork} — and the chain would silently
   * mount the default callback instead of the configured one.
   *
   * @param configured the flat {@code camunda.security.authentication.oidc.redirect-uri}; a blank
   *     value leaves the default callback in place and is accepted
   * @param registrationId the flat block's registration id, which a {@code {registrationId}}
   *     placeholder expands to; a blank one falls back to {@link
   *     OidcConfiguration#DEFAULT_REGISTRATION_ID}, since a flat block that contributes no
   *     registration has no id of its own and the chain mounts the placeholder as a wildcard
   * @throws IllegalArgumentException if the value does not expand to a usable callback URL
   */
  public void validateRedirectionEndpointSource(
      final String configured, final String registrationId) {
    final var id =
        StringUtils.hasText(registrationId)
            ? registrationId
            : OidcConfiguration.DEFAULT_REGISTRATION_ID;
    if (!StringUtils.hasText(configured) || isUsableRedirectUri(configured, id)) {
      return;
    }
    throw new IllegalArgumentException(
        "camunda.security.authentication.oidc.redirect-uri must expand to an absolute http(s) URL"
            + " with a host and a callback path, and without a fragment, because the webapp chain"
            + " mounts its redirection endpoint at that path, but was: "
            + configured
            + ". Spring expands {baseUrl}, {baseScheme}, {baseHost}, {basePort}, {basePath},"
            + " {registrationId} and {action} per request — {basePort} and {basePath} include"
            + " their own ':' and '/' — and expands nothing else.");
  }

  private static void requireRegistrationId(final String registrationId) {
    if (!StringUtils.hasText(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId must be non-blank: set"
              + " camunda.security.authentication.oidc.registration-id (flat block)"
              + " or use a non-blank key under"
              + " camunda.security.authentication.providers.oidc.<id>.*");
    }
  }

  /**
   * Holds the id to what the browser login route needs of it. Only a caller that mounts that route
   * asks: a token decoder or a claims provider uses the id as a registration key and never resolves
   * {@code /oauth2/authorization/<id>}, so an id it can use is no reason to refuse to start.
   */
  private static void requireRegistrationIdAddressableByTheLoginRoute(final String registrationId) {
    if (!isAddressableAsASinglePathSegment(registrationId)) {
      throw new IllegalStateException(
          "OIDC registrationId '"
              + registrationId
              + "' is not addressable as a single path segment. The login route is"
              + " <basePath>/oauth2/authorization/<id>, so an id carrying a URI delimiter or a"
              + " character that has to be escaped resolves to a path that no longer names the"
              + " provider, and a form the default firewall blocks is rejected before the"
              + " authorization filter sees it — and where redirect-uri templates"
              + " {registrationId}, the callback the IdP receives resolves elsewhere too.");
    }
  }

  /**
   * Builds the login route the way {@code LoginLinksBuilder} does, then asks {@link URI} whether
   * the id survives it as one segment and the default firewall whether that route is servable —
   * rather than deciding here which characters are delimiters or blocked forms.
   */
  private static boolean isAddressableAsASinglePathSegment(final String registrationId) {
    try {
      final var loginRoute = new URI(LOGIN_ROUTE_PROBE + registrationId);
      final var path = loginRoute.getPath();
      return loginRoute.getRawQuery() == null
          && loginRoute.getRawFragment() == null
          && path != null
          && registrationId.equals(path.substring(path.lastIndexOf('/') + 1))
          // The login route is an ordinary request, so the firewall rejects an id carrying a
          // blocked form (';', a dot segment) before the authorization filter ever sees it.
          && isServableByTheDefaultFirewall(loginRoute.getRawPath(), path);
    } catch (final URISyntaxException notAddressable) {
      return false;
    }
  }

  /**
   * {@link ClientRegistration.Builder#build()} rejects a blank client-id, so this check only moves
   * that failure to where the misconfiguration is, instead of leaving it to whichever request first
   * resolves the registration.
   */
  private static void requireClientId(final String registrationId, final OidcConfiguration oidc) {
    if (!StringUtils.hasText(oidc.getClientId())) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': client-id must be non-blank. Set it under"
              + " camunda.security.authentication.oidc.client-id (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".client-id.");
    }
  }

  /**
   * The build path turns this value into a {@link ClientAuthenticationMethod}, which rejects a
   * blank one, so constructing it here is what moves that failure to where the misconfiguration is.
   */
  private static void requireClientAuthenticationMethod(
      final String registrationId, final OidcConfiguration oidc) {
    try {
      new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod());
    } catch (final IllegalArgumentException rejected) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': client-authentication-method must be non-blank. Set it under"
              + " camunda.security.authentication.oidc.client-authentication-method (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".client-authentication-method.",
          rejected);
    }
  }

  /**
   * {@link ClientRegistration.Builder#build()} rejects a scope containing a character RFC 6749
   * excludes from a scope token — a space, most notably, which is what a single {@code scope} entry
   * holding a space-separated list amounts to. Running that validation on a probe registration
   * leaves the rule with Spring and needs no network, so the misconfiguration fails at startup
   * rather than on the first authorization request.
   */
  private static void requireUsableScopes(
      final String registrationId, final OidcConfiguration oidc) {
    if (oidc.getScope() == null) {
      return;
    }
    try {
      ClientRegistration.withRegistrationId(registrationId)
          .clientId(oidc.getClientId())
          .redirectUri(BASE_URL_PLACEHOLDER)
          .authorizationUri("https://probe.invalid/auth")
          .tokenUri("https://probe.invalid/token")
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .scope(oidc.getScope())
          .build();
    } catch (final IllegalArgumentException rejected) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': "
              + rejected.getMessage()
              + ". A scope is one entry per value, not a space-separated list. Set them under"
              + " camunda.security.authentication.oidc.scope (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".scope.",
          rejected);
    }
  }

  /**
   * Every endpoint a provider block can configure names a location the application sends HTTP
   * requests to, so each has to be an absolute http(s) URL. Checking their syntax needs no network
   * access, which keeps a typo a startup failure even where the request itself happens later.
   */
  private static void requireAbsoluteEndpointUrls(
      final String registrationId, final OidcConfiguration oidc) {
    requireAbsoluteHttpUrl(registrationId, "issuer-uri", oidc.getIssuerUri());
    requireAbsoluteHttpUrl(registrationId, "authorization-uri", oidc.getAuthorizationUri());
    requireAbsoluteHttpUrl(registrationId, "token-uri", oidc.getTokenUri());
    requireAbsoluteHttpUrl(registrationId, "jwk-set-uri", oidc.getJwkSetUri());
    if (oidc.isUserInfoEnabled()) {
      // A disabled provider has its userInfoUri nulled on the build path, so a stale value there is
      // never requested — validating it would fail a deployment that works today.
      requireAbsoluteHttpUrl(registrationId, "user-info-uri", oidc.getUserInfoUri());
    }
    requireAbsoluteHttpUrl(
        registrationId, "end-session-endpoint-uri", oidc.getEndSessionEndpointUri());
    if (oidc.getAdditionalJwkSetUris() != null) {
      oidc.getAdditionalJwkSetUris()
          .forEach(uri -> requireAbsoluteHttpUrl(registrationId, "additional-jwk-set-uris", uri));
    }
  }

  private static void requireAbsoluteHttpUrl(
      final String registrationId, final String property, final String value) {
    if (!StringUtils.hasText(value)) {
      return;
    }
    final URI parsed;
    try {
      parsed = new URI(value);
    } catch (final URISyntaxException malformed) {
      throw new IllegalStateException(endpointUrlError(registrationId, property, value), malformed);
    }
    final var scheme = parsed.getScheme();
    if (!parsed.isAbsolute()
        || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
        || !StringUtils.hasText(parsed.getHost())
        || !namesAPortInTcpRange(parsed)) {
      throw new IllegalStateException(endpointUrlError(registrationId, property, value));
    }
  }

  /**
   * Whether a URL names a port a TCP connection can be opened to. {@code -1} is {@link
   * URI#getPort()} for a URL that omits it, leaving the scheme's default.
   */
  private static boolean namesAPortInTcpRange(final URI uri) {
    final var port = uri.getPort();
    return port == -1 || (port >= 1 && port <= 65535);
  }

  private static String endpointUrlError(
      final String registrationId, final String property, final String value) {
    return "Cannot build ClientRegistration '"
        + registrationId
        + "': "
        + property
        + " must be an absolute http(s) URL with a host and, if it names a port, one in 1-65535,"
        + " but was: "
        + value
        + ". Set camunda.security.authentication.oidc."
        + property
        + " (flat) or camunda.security.authentication.providers.oidc."
        + registrationId
        + "."
        + property
        + ".";
  }

  private static void requireEndpointConfiguration(
      final String registrationId, final OidcConfiguration oidc) {
    if (StringUtils.hasText(oidc.getIssuerUri())
        || (StringUtils.hasText(oidc.getAuthorizationUri())
            && StringUtils.hasText(oidc.getTokenUri())
            && StringUtils.hasText(oidc.getJwkSetUri()))) {
      return;
    }
    throw new IllegalStateException(
        "Cannot build ClientRegistration '"
            + registrationId
            + "': set issuer-uri, or all of authorization-uri, token-uri, and jwk-set-uri,"
            + " under camunda.security.authentication.oidc.* (flat) or"
            + " camunda.security.authentication.providers.oidc."
            + registrationId
            + ".*");
  }

  /**
   * A non-blank path without a leading '/' would produce "{baseUrl}physical-tenants/..." which is
   * not a valid URI — reject it early so the caller gets a clear error instead of a subtle misuse.
   * What the path expands to is judged per registration in {@link #resolveRedirectUri}.
   */
  private static void requireAbsoluteScopedRedirectUriPath(final String scopedRedirectUriPath) {
    if (StringUtils.hasText(scopedRedirectUriPath) && !scopedRedirectUriPath.startsWith("/")) {
      throw new IllegalArgumentException(
          "scopedRedirectUriPath must start with '/', but was: " + scopedRedirectUriPath);
    }
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
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
    requireRegistrationId(registrationId);
    requireClientId(registrationId, oidc);
    requireClientAuthenticationMethod(registrationId, oidc);
    requireUsableScopes(registrationId, oidc);
    requireAbsoluteEndpointUrls(registrationId, oidc);
    final var redirectUri =
        resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks);
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
   *       must expand to an absolute URL — see {@link #isUsableRedirectUri} and {@link
   *       OidcConfiguration#getRedirectUri()};
   *   <li>the {@code {baseUrl}/sso-callback} default, matching the redirection endpoint registered
   *       under {@link OidcRedirectionEndpoint#DEFAULT_PATH}.
   * </ol>
   *
   * <p>The default lets a provider that omits {@code redirect-uri} still complete the login flow,
   * matching the behaviour of OC's former {@code ClientRegistrationFactory}.
   *
   * @throws IllegalArgumentException if the configured {@code redirect-uri} does not expand to a
   *     usable callback URL
   */
  private String resolveRedirectUri(
      final String registrationId,
      final OidcConfiguration oidc,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
    final var checkCallback = loginRouteChecks == LoginRouteChecks.ENFORCED;
    if (StringUtils.hasText(scopedRedirectUriPath)) {
      final var scoped = BASE_URL_PLACEHOLDER + scopedRedirectUriPath;
      if (checkCallback && !isUsableRedirectUri(scoped, registrationId)) {
        throw new IllegalArgumentException(
            "scopedRedirectUriPath must yield a callback this application can serve: a path the"
                + " default firewall lets through, and one the scoped chain's redirection endpoint"
                + " matches once expanded — no empty or dot segment, semicolon, backslash,"
                + " percent escape or control character, but was: "
                + scopedRedirectUriPath);
      }
      return scoped;
    }
    if (StringUtils.hasText(oidc.getRedirectUri())) {
      final String configured = oidc.getRedirectUri();
      if (checkCallback && !isUsableRedirectUri(configured, registrationId)) {
        throw new IllegalArgumentException(
            "Cannot build ClientRegistration '"
                + registrationId
                + "': redirect-uri must expand to an absolute http(s) URL with a host, a port in"
                + " 1-65535 if it names one, and a callback path, and without a fragment, because"
                + " that is where the IdP redirects"
                + " the browser, and the redirection endpoint derived from this value has to match"
                + " that same expanded path,"
                + " but was: "
                + configured
                + ". Spring expands {baseUrl}, {baseScheme}, {baseHost}, {basePort}, {basePath},"
                + " {registrationId} and {action} per request — {basePort} and {basePath} include"
                + " their own ':' and '/' — and expands nothing else."
                + " Set camunda.security.authentication.oidc.redirect-uri (flat) or"
                + " camunda.security.authentication.providers.oidc."
                + registrationId
                + ".redirect-uri.");
      }
      return configured;
    }
    return BASE_URL_PLACEHOLDER + OidcRedirectionEndpoint.DEFAULT_PATH;
  }

  /**
   * Whether the configured redirect-uri yields a callback both the IdP and this application can
   * use, under every {@link #sampleRequestShapes request shape} of this registration. It has to
   * expand — as {@code DefaultOAuth2AuthorizationRequestResolver} expands it, same builder and
   * variable names — to an absolute http(s) URL with a host, a port a TCP connection can be opened
   * to and a path, carry no fragment (RFC 6749, section 3.1.2, forbids one; a query is allowed and
   * is passed on to the IdP) and a path {@link #isServableByTheDefaultFirewall the default firewall
   * lets through}, and name a callback {@link #callbackMatchesTheRedirectionEndpoint the
   * redirection endpoint derived from it matches}.
   *
   * <p>Expanding rather than modelling which placeholder yields what leaves no rule of ours to keep
   * current: a placeholder the resolver cannot expand, one that leaves the authority incomplete and
   * a template that is no URL at all all fail on the expansion itself.
   */
  private boolean isUsableRedirectUri(final String configured, final String registrationId) {
    return sampleRequestShapes(registrationId).stream()
        .allMatch(uriVariables -> isUsableForRequestShape(configured, uriVariables));
  }

  /**
   * Whether the redirection endpoint {@link OidcRedirectionEndpoint#resolve} derives from this
   * redirect-uri matches the callback path the expansion produced — the agreement between the two
   * consumers of the value. Routing is out of scope: neither whether a chain mounts this provider's
   * value, nor whether a chain's own {@code securityMatcher} selects it for the callback request,
   * follows from the value alone. Both come from the host's {@code SecurityPathPort}.
   */
  private static boolean callbackMatchesTheRedirectionEndpoint(
      final String configured, final URI expanded, final String contextPath) {
    final String endpointPath;
    try {
      endpointPath =
          OidcRedirectionEndpoint.resolve(
              configured, contextPath, OidcRedirectionEndpoint.DEFAULT_PATH);
    } catch (final IllegalArgumentException noCallbackPath) {
      return false;
    }
    final var callbackPath =
        OidcRedirectionEndpoint.stripContextPath(expanded.getPath(), contextPath);
    try {
      return PathPatternParser.defaultInstance
          .parse(endpointPath)
          .matches(PathContainer.parsePath(callbackPath));
    } catch (final PatternParseException noPattern) {
      return false;
    }
  }

  private static boolean isServableByTheDefaultFirewall(final String rawPath, final String path) {
    final var blocklisted = rawPath.toLowerCase(Locale.ROOT);
    return REJECTED_BY_THE_DEFAULT_FIREWALL.stream().noneMatch(blocklisted::contains)
        && Arrays.stream(rawPath.split("/", -1)).noneMatch(DOT_SEGMENTS::contains)
        && path.chars().noneMatch(c -> Character.isISOControl(c) || c == '\u2028' || c == '\u2029');
  }

  private static boolean isUsableForRequestShape(
      final String configured, final Map<String, String> uriVariables) {
    final URI expanded;
    try {
      expanded =
          new URI(
              UriComponentsBuilder.fromUriString(configured)
                  .buildAndExpand(uriVariables)
                  .toUriString());
    } catch (final IllegalArgumentException | URISyntaxException cannotExpand) {
      return false;
    }
    final var scheme = expanded.getScheme();
    return expanded.isAbsolute()
        && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
        && StringUtils.hasText(expanded.getHost())
        && namesAPortInTcpRange(expanded)
        && StringUtils.hasText(expanded.getPath())
        && isServableByTheDefaultFirewall(expanded.getRawPath(), expanded.getPath())
        && expanded.getRawFragment() == null
        && callbackMatchesTheRedirectionEndpoint(
            configured, expanded, uriVariables.get("basePath"));
  }

  /**
   * Builds the base {@link ClientRegistration.Builder}: discovery via {@code issuer-uri} when set,
   * otherwise an empty builder; in both cases any explicitly-configured endpoint URI on {@link
   * OidcConfiguration} overrides the discovered value. A non-blank value on the configuration
   * always wins; a null/blank value leaves the discovered value untouched. The one exception is
   * {@code userNameAttributeName}, which is not adopter-configured at all: see {@link
   * #applyExplicitEndpointOverrides}.
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

    requireEndpointConfiguration(registrationId, oidc);

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
   * the configuration always wins and a null/blank one leaves the discovered value untouched. The
   * one exception is {@code userNameAttributeName}: it is not an endpoint URI and not adopter
   * configured, but is written unconditionally whenever {@code userInfoUri} is set, to mirror what
   * discovery already does for the {@code issuer-uri} path (see below).
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
      // Discovery (fromIssuerLocation) sets this unconditionally to "sub"; the manual-endpoint
      // path needs the same default, or DefaultOAuth2UserService throws
      // missing_user_name_attribute on every login as soon as a UserInfo endpoint is configured.
      // Deliberately not oidc.getUsernameClaim(): that field may be a JSONPath expression
      // (OidcPrincipalLoader), which would then be missing from the flat UserInfo response.
      builder.userNameAttributeName(IdTokenClaimNames.SUB);
    }
    return builder;
  }
}
