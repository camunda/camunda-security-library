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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
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

  /**
   * The URI template variables Spring populates when it expands {@code post_logout_redirect_uri}.
   * Anything else throws from {@code buildAndExpand} at logout, so a value naming one is rejected
   * here instead.
   */
  private static final String BASE_SCHEME_PLACEHOLDER = "{baseScheme}";

  private static final String BASE_HOST_PLACEHOLDER = "{baseHost}";
  private static final String BASE_PORT_PLACEHOLDER = "{basePort}";
  private static final String BASE_PATH_PLACEHOLDER = "{basePath}";

  /** The placeholders that bring their own delimiter and so may trail a host. */
  private static final List<String> AUTHORITY_TRAILING_PLACEHOLDERS =
      List.of(BASE_PATH_PLACEHOLDER, BASE_PORT_PLACEHOLDER);

  /** RFC 3986 §3.1. */
  private static final Pattern URI_SCHEME = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*");

  /** What a mistyped template variable looks like; see {@link #unsupportedVariable}. */
  private static final Pattern SAFE_VARIABLE_NAME = Pattern.compile("[A-Za-z0-9_-]{1,40}");

  private static final Set<String> POST_LOGOUT_TEMPLATE_VARIABLES =
      Set.of("baseUrl", "baseScheme", "baseHost", "basePort", "basePath", "registrationId");

  /** The login route that {@code LoginLinksBuilder} makes. The id checks use the same route. */
  private static final String LOGIN_ROUTE_PROBE = "https://probe.invalid/oauth2/authorization/";

  /**
   * Substrings that the default {@code StrictHttpFirewall} of Spring Security does not permit in a
   * request URL. The firewall rejects such a request before it examines a filter chain. If a
   * redirect-uri expands to a path with one of these substrings, no component can answer the
   * callback. A test in {@code ScopedClientRegistrationFactoryTest} compares this list with the
   * firewall itself.
   */
  private static final List<String> REJECTED_BY_THE_DEFAULT_FIREWALL =
      List.of("//", ";", "%3b", "%2f", "\\", "%5c", "%25", "%2e", "%00", "%0a", "%0d");

  /**
   * Segments that the same firewall rejects, because the request URL is then not normalized. A
   * callback that contains such a segment is also unreachable.
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

  /** The context path of the deployment, in the form {@code request.getContextPath()} reports. */
  private final String basePath;

  /** Makes a factory for a deployment that has no servlet context path. */
  public ScopedClientRegistrationFactory() {
    this("");
  }

  /**
   * @param servletContextPath the configured {@code server.servlet.context-path}, or {@code ""} if
   *     it is not set. {@link OidcRedirectionEndpoint#resolve} uses the same unchanged value. Both
   *     components therefore examine a redirect-uri under the real context path of the deployment.
   */
  public ScopedClientRegistrationFactory(final String servletContextPath) {
    basePath = contextPathAsTheServletReportsIt(servletContextPath);
  }

  /**
   * Substitute values for the request data that {@code DefaultOAuth2AuthorizationRequestResolver}
   * expands a redirect-uri with. Each shape carries the context path of the deployment and the id
   * of the registration. The shapes differ in the port, because {@code basePort} expands with its
   * own {@code :} only if the port is not the default port. A template that supplies the {@code :}
   * itself is therefore absolute in the first shape and incorrect in the second shape.
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
   * The resolver expands {@code basePath} from {@code request.getContextPath()}. This method
   * therefore removes the trailing slash from a configured value such as {@code /orchestration/}.
   * With the trailing slash, the factory examines the redirect-uri against a callback that has an
   * empty path segment, and no request can carry such a segment.
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
   * Creates one {@link ClientRegistration} for each entry in the provider map. The method uses the
   * map key as the {@code registrationId}.
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
   * Creates one {@link ClientRegistration} for each entry in the provider map. If {@code
   * scopedRedirectUriPath} is not null and not blank, the method replaces the {@code redirect_uri}
   * of each registration with that path. The method validates the complete map with {@link
   * #validateWithoutNetwork} first. It therefore reports an incorrect entry before it contacts the
   * issuer of an earlier entry for discovery.
   *
   * <p>The redirection endpoint of the scoped webapp chain listens at a path with a prefix, for
   * example {@code /physical-tenants/{id}/sso-callback}. The registrations must carry a {@code
   * redirect_uri} that agrees with that path. Without the replacement, the IdP calls back to the
   * cluster path that has no prefix, and the scoped chain does not intercept that path.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @param scopedRedirectUriPath the path to use as the redirect-uri, for example {@code
   *     /physical-tenants/t1/sso-callback}. If it is {@code null} or blank, the method keeps the
   *     redirect-uri from the {@link OidcConfiguration}.
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank but is not a path the
   *     default firewall lets through, or a configured redirect-uri does not expand to a usable
   *     callback URL
   * @throws IllegalStateException if any provider block fails one of the checks {@link
   *     #validateWithoutNetwork} describes
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    return createFromProviderMap(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  /**
   * Creates one {@link ClientRegistration} for each entry, for a caller that derives no browser
   * login route from the configuration. Two callers do this: the token validation of an API chain,
   * and UserInfo augmentation. Both read the issuer, the keys and the endpoints of a registration,
   * and neither redirects a browser.
   *
   * <p>The method makes each check on a value that such a caller uses. It does not make the {@link
   * LoginRouteChecks login chain checks}. If no login chain exists, a redirect-uri the application
   * cannot serve, a registration id the login route cannot address, and a malformed end-session
   * endpoint are no reason to stop the application. The login paths are the webapp client beans and
   * the webapp chains. They continue to reject each of these values, because they are the paths
   * where such a value breaks the flow.
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
   * The same as {@link #createWithoutLoginRoutes(Map)}, but the method flattens the {@link
   * AuthenticationConfiguration} first.
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
   * Flattens the {@link AuthenticationConfiguration} and then builds all {@link ClientRegistration}
   * instances from the result.
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
   * Makes each check that {@link #createFromProviderMap(Map, String)} makes without network access,
   * and builds no registration. A caller that resolves registrations only when it needs them can
   * therefore reject an incorrect provider block at startup. The failure then occurs where the
   * configuration is, and not on the first request that needs the block.
   *
   * @throws IllegalStateException if Spring cannot make a {@link ClientRegistration} from a
   *     provider block. The causes are a blank registrationId, client-id or
   *     client-authentication-method, a registrationId that the login route cannot address as one
   *     path segment, a scope that contains a character a scope token does not permit, a configured
   *     endpoint URL that is not an absolute http(s) URL with a host and a port in the TCP range,
   *     and a block that sets neither issuer-uri nor all of authorization-uri, token-uri and
   *     jwk-set-uri. The method reports an incorrect URL before the completeness error that the URL
   *     causes.
   * @throws IllegalArgumentException if {@code scopedRedirectUriPath} is not absolute, or is a path
   *     the default firewall does not permit, or if a configured redirect-uri does not expand to a
   *     usable callback URL
   */
  public void validateWithoutNetwork(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    validateWithoutNetwork(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  /**
   * As {@link #validateWithoutNetwork}, for a caller that derives no browser login route from the
   * configuration. See {@link #createWithoutLoginRoutes(Map)}.
   *
   * @throws IllegalStateException if a provider block does not pass one of the checks that {@link
   *     #validateWithoutNetwork} describes, other than the login-route checks
   */
  public void validateWithoutLoginRoutes(final Map<String, OidcConfiguration> providers) {
    validateWithoutNetwork(providers, null, LoginRouteChecks.SKIPPED);
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
          requireAbsoluteEndpointUrls(registrationId, oidc, loginRouteChecks);
          if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
            // Only a caller mounting the browser login chain mounts the logout handler, which is
            // the
            // sole consumer of this value — the same reasoning that gates end-session-endpoint-uri.
            requirePostLogoutRedirectUri(registrationId, oidc);
          }
          requireEndpointConfiguration(registrationId, oidc);
          requireUserInfoRequiredConsistency(registrationId, oidc);
          resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks);
        });
  }

  /**
   * Tells if the caller mounts the browser login chain. Such a caller derives the login route from
   * the registration id, and the redirection endpoint from the redirect-uri. It also mounts the
   * logout handler, which is the only consumer of the end-session endpoint. The factory makes each
   * of these checks only for such a caller.
   */
  private enum LoginRouteChecks {
    ENFORCED,
    SKIPPED
  }

  /**
   * Validates the flat {@code redirect-uri} that the unscoped webapp chain uses for its redirection
   * endpoint. The method applies the same contract as for a value in a provider block. The flat
   * block decides that endpoint also if it adds no registration. A value without a {@code
   * client-id} therefore never reaches {@link #validateWithoutNetwork}, and the chain mounts the
   * default callback instead of the configured callback.
   *
   * @param configured the flat {@code camunda.security.authentication.oidc.redirect-uri}. The
   *     method accepts a blank value, and the default callback stays in use.
   * @param registrationId the registration id of the flat block, which a {@code {registrationId}}
   *     placeholder expands to. If it is blank, the method uses {@link
   *     OidcConfiguration#DEFAULT_REGISTRATION_ID}, because a flat block that adds no registration
   *     has no id of its own, and the chain mounts the placeholder as a wildcard.
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
            + UrlRedaction.redact(configured)
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
   * Applies to the id the conditions of the browser login route. Only a caller that mounts that
   * route makes this check. A token decoder or a claims provider uses the id as a registration key
   * and never resolves {@code /oauth2/authorization/<id>}. An id that such a caller can use is
   * therefore no reason to stop the application.
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
              + " {registrationId}, the callback the IdP receives resolves elsewhere too. Set"
              + " camunda.security.authentication.oidc.registration-id (flat block) or rename the"
              + " key under camunda.security.authentication.providers.oidc.<id>.");
    }
  }

  /**
   * Makes the login route in the same way as {@code LoginLinksBuilder}. The method then asks {@link
   * URI} if the id stays one segment in that route, and asks the default firewall if it permits the
   * route. This class therefore does not decide which characters are delimiters or forbidden forms.
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
   * {@link ClientRegistration.Builder#build()} rejects a blank client-id. This check only moves
   * that failure to startup, away from the first request that resolves the registration.
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
   * The check makes the {@link ClientAuthenticationMethod} that the build path makes. Spring
   * therefore keeps the rule, and the failure occurs at startup and not on the first request that
   * needs the registration.
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
   * {@link ClientRegistration.Builder#build()} rejects a scope that contains a character that RFC
   * 6749 does not permit in a scope token. The most frequent such character is a space. A space
   * occurs if one {@code scope} entry holds a list that spaces separate. The check makes that
   * validation on a probe registration. Spring therefore keeps the rule, and the check needs no
   * network.
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
   * Each endpoint in a provider block is an address to which the application sends requests. A
   * check of these addresses needs no network. A typo therefore causes a failure at startup, also
   * if the related request occurs much later. Two endpoints are exempt where nothing dereferences
   * them: a {@code user-info-uri} that the build path discards, and the end-session endpoint of a
   * caller that mounts no login chain.
   */
  private static void requireAbsoluteEndpointUrls(
      final String registrationId,
      final OidcConfiguration oidc,
      final LoginRouteChecks loginRouteChecks) {
    requireAbsoluteHttpUrl(registrationId, "issuer-uri", oidc.getIssuerUri());
    requireAbsoluteHttpUrl(registrationId, "authorization-uri", oidc.getAuthorizationUri());
    requireAbsoluteHttpUrl(registrationId, "token-uri", oidc.getTokenUri());
    requireAbsoluteHttpUrl(registrationId, "jwk-set-uri", oidc.getJwkSetUri());
    if (oidc.isUserInfoEnabled()) {
      // A disabled provider has its userInfoUri nulled on the build path, so a stale value there is
      // never requested — validating it would fail a deployment that works today.
      requireAbsoluteHttpUrl(registrationId, "user-info-uri", oidc.getUserInfoUri());
    }
    if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
      // CamundaOidcLogoutSuccessHandler is the only consumer, and it exists on the webapp login
      // chain. A caller that mounts no such chain never dereferences the value.
      requireAbsoluteHttpUrl(
          registrationId, "end-session-endpoint-uri", oidc.getEndSessionEndpointUri());
    }
    if (oidc.getAdditionalJwkSetUris() != null) {
      oidc.getAdditionalJwkSetUris()
          .forEach(uri -> requireAbsoluteHttpUrl(registrationId, "additional-jwk-set-uris", uri));
    }
  }

  /**
   * Rejects a {@code post-logout-redirect-uri} that cannot work, before a logout ever runs.
   *
   * <p>Three accepted shapes: a path starting with {@code /}, which the logout chain resolves
   * against its own base path; an absolute URL; or a URI template that still resolves to an
   * absolute URL once Spring expands it. The template form is what lets a deployment served under a
   * per-cluster prefix name a URL its IdP can actually have registered, so it cannot simply be
   * disallowed.
   *
   * <p>Everything here fails at startup rather than at logout, which is the point: Spring expands
   * the template on the logout request itself, so an unexpandable value throws from inside {@code
   * buildAndExpand} on the one request a user cannot usefully retry — long after the typo shipped.
   *
   * <p>See ADR-0026.
   */
  /**
   * Validates only the {@code post-logout-redirect-uri} of each provider.
   *
   * <p>{@link #validateWithoutNetwork} already runs this as part of a full provider-block check,
   * and that is the path a normal deployment takes. This narrower entry point exists for the
   * consumer that can reach a provider map the factory never built: the primary chain's {@code
   * ClientRegistrationRepository} bean is {@code @ConditionalOnMissingBean}, so a host can replace
   * it and bypass {@code createFromProviderMap} entirely, while the logout handler is still
   * configured from the provider-configuration port. Without this the values it composes would
   * never have been checked.
   *
   * <p>Running twice is harmless — the checks are pure — and the alternative, a second copy of the
   * rules at the consumer, is what keeping one implementation is meant to avoid.
   *
   * @param providers the provider configurations keyed by registration id; must not be {@code null}
   * @throws IllegalStateException if any configured value cannot work
   */
  public void validatePostLogoutRedirectUris(final Map<String, OidcConfiguration> providers) {
    Objects.requireNonNull(providers, "providers must not be null");
    providers.forEach(this::requirePostLogoutRedirectUri);
  }

  private void requirePostLogoutRedirectUri(
      final String registrationId, final OidcConfiguration oidc) {
    final var configured = oidc.getPostLogoutRedirectUri();
    if (!StringUtils.hasText(configured)) {
      return;
    }
    final var value = configured.trim();
    // Covers CR and LF, which would otherwise forge a line in the log this error is written to,
    // and the rest of the control characters, which no component can serve.
    if (value.chars().anyMatch(Character::isISOControl)) {
      throw postLogoutRedirectUriError(
          registrationId, value, "must not contain control characters");
    }
    // OpenID Connect RP-Initiated Logout 1.0 §2 gives post_logout_redirect_uri no fragment, so an
    // OP has no reason to accept one.
    if (value.indexOf('#') >= 0) {
      throw postLogoutRedirectUriError(registrationId, value, "must not contain a fragment ('#')");
    }
    requireExpandableTemplate(registrationId, value);
    if (!value.startsWith("/")) {
      requireUsableAbsoluteForm(registrationId, value);
    }
    if (!isUsablePostLogoutRedirectUri(value, registrationId)) {
      throw postLogoutRedirectUriError(
          registrationId,
          value,
          "must expand to an absolute http(s) URL with a host, a port in 1-65535 if it names one,"
              + " and no fragment");
    }
  }

  /** The checks that only a non-path value can fail. */
  private static void requireUsableAbsoluteForm(final String registrationId, final String value) {
    if (!continuesWithAPath(value)) {
      throw postLogoutRedirectUriError(
          registrationId,
          value,
          "must continue with a path after {baseUrl}, which already carries the scheme, host and"
              + " port");
    }
    if (!resolvesToAnAbsoluteUrl(value)) {
      throw postLogoutRedirectUriError(
          registrationId,
          value,
          "must be an absolute URL, a path starting with '/', or a template that still resolves to"
              + " an absolute URL (starting with {baseUrl}, or carrying an explicit scheme and a"
              + " host, such as {baseScheme}://{baseHost})");
    }
    requireParseableAbsoluteUrl(registrationId, value);
  }

  /**
   * Whether the value is still a usable URL once expanded, for every request shape.
   *
   * <p>The structural checks above catch what expansion cannot — a placeholder standing where the
   * scheme belongs survives expansion as a perfectly valid URL — and this catches what they cannot:
   * a literal {@code %zz} in the path, a port that expands out of range, and the several ways a
   * value can be correct on one request and malformed on another.
   *
   * <p>{@link #sampleRequestShapes} is the same two-shape probe {@code redirect-uri} is held to,
   * and the second shape is the one that matters here: {@code basePort} expands with its own {@code
   * ':'} only on a non-default port, so a template that also supplies one is right on the first
   * shape and wrong on the second.
   *
   * <p>A path is expanded under {@code {baseUrl}}, which is how the chain composes it.
   */
  private boolean isUsablePostLogoutRedirectUri(
      final String configured, final String registrationId) {
    final var template =
        configured.startsWith("/") ? BASE_URL_PLACEHOLDER + configured : configured;
    return sampleRequestShapes(registrationId).stream()
        .allMatch(uriVariables -> expandsToAUsablePostLogoutUrl(template, uriVariables));
  }

  private static boolean expandsToAUsablePostLogoutUrl(
      final String template, final Map<String, String> uriVariables) {
    final URI expanded;
    try {
      expanded =
          new URI(
              UriComponentsBuilder.fromUriString(template)
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
        && expanded.getRawFragment() == null;
  }

  /**
   * Whether a {@code {baseUrl}} value carries on with a path.
   *
   * <p>{@code {baseUrl}} already expands to scheme, host, port and context path, so anything but a
   * path after it duplicates a component: {@code {baseUrl}:8080/logout} becomes {@code
   * https://host:8443:8080/logout} on a non-default port. Only the shape rule catches this — the
   * value expands to something a URI parser still accepts on a default-port request.
   */
  private static boolean continuesWithAPath(final String value) {
    if (!value.startsWith(BASE_URL_PLACEHOLDER)) {
      return true;
    }
    final var rest = value.substring(BASE_URL_PLACEHOLDER.length());
    return rest.isEmpty() || rest.startsWith("/") || rest.startsWith("?");
  }

  /**
   * Whether a non-path value still yields an absolute URL once Spring expands it.
   *
   * <p>A leading {@code {baseUrl}} does by definition. Otherwise the value needs a usable scheme
   * <em>and</em> a usable authority, and each has a trap of its own.
   *
   * <p>The scheme has to be a real scheme or {@code {baseScheme}}, not merely a {@code "://"}
   * somewhere in the string: {@code {basePath}https://host/logout} contains one and expands to
   * {@code /prefix...https://host/logout}, which is relative.
   *
   * <p>The authority has to be able to hold a host and, if it names a port, a number. {@code
   * https://{basePath}/goodbye} carries a scheme and only supported placeholders, yet expands to
   * {@code https:///goodbye} with no host; {@code https://host:{registrationId}/logout} expands to
   * a port of {@code oidc}. {@code {baseHost}} and {@code {basePort}} are the two placeholders that
   * do belong here — {@code basePort} carries its own {@code ':'} — so they are allowed by name.
   */
  private static boolean resolvesToAnAbsoluteUrl(final String value) {
    if (value.startsWith(BASE_URL_PLACEHOLDER)) {
      return true;
    }
    final var schemeEnd = value.indexOf("://");
    return schemeEnd >= 0
        && isUsableScheme(value.substring(0, schemeEnd))
        && isUsableAuthority(authorityOf(value, schemeEnd + 3));
  }

  private static boolean isUsableScheme(final String scheme) {
    return BASE_SCHEME_PLACEHOLDER.equals(scheme) || URI_SCHEME.matcher(scheme).matches();
  }

  /** The authority: everything up to the first {@code '/'}, {@code '?'} or {@code '#'}. */
  private static String authorityOf(final String value, final int from) {
    var end = value.length();
    for (final char delimiter : new char[] {'/', '?', '#'}) {
      final var at = value.indexOf(delimiter, from);
      if (at >= 0 && at < end) {
        end = at;
      }
    }
    return value.substring(from, end);
  }

  private static boolean isUsableAuthority(final String authority) {
    // {basePort} carries its own ':' and {basePath} its own '/', so either can legitimately trail
    // the host and neither ends the authority the way a literal delimiter would. Peel them off —
    // both, in any order — before looking at what is left.
    var host = authority;
    var peeled = true;
    while (peeled) {
      peeled = false;
      for (final String placeholder : AUTHORITY_TRAILING_PLACEHOLDERS) {
        if (host.endsWith(placeholder)) {
          host = host.substring(0, host.length() - placeholder.length());
          peeled = true;
        }
      }
    }
    // A ':' left behind is one the value supplied itself, on top of the one {basePort} brings.
    if (host.endsWith(":")) {
      return false;
    }
    String port = null;
    // Last ':' after any ']' so an IPv6 literal's own colons are not mistaken for a port.
    final var colon = host.lastIndexOf(':');
    if (colon > host.lastIndexOf(']')) {
      port = host.substring(colon + 1);
      host = host.substring(0, colon);
    }
    final var hostIsUsable =
        BASE_HOST_PLACEHOLDER.equals(host) || (!host.isEmpty() && host.indexOf('{') < 0);
    final var portIsUsable =
        port == null || (!port.isEmpty() && port.chars().allMatch(Character::isDigit));
    return hostIsUsable && portIsUsable;
  }

  /**
   * Rejects a template Spring cannot expand: an unbalanced brace, or a placeholder outside the
   * fixed set its post-logout expansion populates.
   *
   * <p>Scans rather than regex-matches because a regex for a brace-delimited name only sees
   * <em>closed</em> pairs, and the open ones are the dangerous case. {@code UriComponentsBuilder}
   * does not reject an unclosed brace: <code>&#123;baseUrl&#125;&#123;tenantId</code> expands to
   * the literal <code>https://host&#123;tenantId</code> and is sent to the IdP exactly like that. A
   * closed-pair check would find only {@code baseUrl}, pass it, and ship the malformed URL.
   */
  private static void requireExpandableTemplate(final String registrationId, final String value) {
    int openAt = -1;
    for (int i = 0; i < value.length(); i++) {
      final char c = value.charAt(i);
      if (c == '{') {
        if (openAt >= 0) {
          throw postLogoutRedirectUriError(registrationId, value, "contains a nested '{'");
        }
        openAt = i;
      } else if (c == '}') {
        if (openAt < 0) {
          throw postLogoutRedirectUriError(registrationId, value, "contains an unmatched '}'");
        }
        final var name = value.substring(openAt + 1, i);
        if (!POST_LOGOUT_TEMPLATE_VARIABLES.contains(name)) {
          throw postLogoutRedirectUriError(
              registrationId,
              value,
              "uses "
                  + unsupportedVariable(name)
                  + "; supported variables are "
                  + POST_LOGOUT_TEMPLATE_VARIABLES);
        }
        openAt = -1;
      }
    }
    if (openAt >= 0) {
      throw postLogoutRedirectUriError(registrationId, value, "contains an unclosed '{'");
    }
  }

  /**
   * Parses whatever part of the value is already literal.
   *
   * <p>Skipping the parse for any value containing a placeholder was too coarse: {@code https://ex
   * ample.com/{basePath}} has a perfectly literal — and malformed — host, and only the templated
   * path made it skip. So the authority is parsed whenever it holds no placeholder, and the whole
   * value only when nothing at all is templated.
   *
   * <p>A {@code {baseScheme}} is parsed as {@code https}: the scheme is unknown until the request,
   * but standing one in is what lets the authority after it be checked at all.
   */
  private static void requireParseableAbsoluteUrl(final String registrationId, final String value) {
    if (value.startsWith(BASE_URL_PLACEHOLDER)) {
      return;
    }
    final var schemeEnd = value.indexOf("://");
    final var scheme = value.substring(0, schemeEnd);
    final var authority = authorityOf(value, schemeEnd + 3);
    if (authority.indexOf('{') >= 0) {
      return;
    }
    final var probeScheme = BASE_SCHEME_PLACEHOLDER.equals(scheme) ? "https" : scheme;
    final var probe =
        value.indexOf('{') < 0
            ? probeScheme + value.substring(schemeEnd)
            : probeScheme + "://" + authority;
    final URI parsed;
    try {
      parsed = new URI(probe);
    } catch (final URISyntaxException malformed) {
      throw postLogoutRedirectUriError(
          registrationId, value, "is not a valid URI: " + malformed.getReason());
    }
    if (!parsed.isAbsolute() || !StringUtils.hasText(parsed.getHost())) {
      throw postLogoutRedirectUriError(registrationId, value, "is missing a scheme or a host");
    }
    if (!namesAPortInTcpRange(parsed)) {
      throw postLogoutRedirectUriError(
          registrationId, value, "must name a port in 1-65535 if it names one");
    }
  }

  /**
   * Names the offending variable only when the name looks like one.
   *
   * <p>Whatever sits between the braces is operator-supplied and reaches this message before the
   * value itself is redacted, so echoing it unconditionally re-opens the hole the redaction closes
   * — {@code {https://user:password@host}} is a syntactically valid thing to write. A real typo is
   * a short identifier; anything else is named generically, and the supported list below is the
   * actionable part either way.
   *
   * <p>Supersedes the inline guard in f4ff08d, which substituted {@code "?"} for an unsafe name.
   * Same rule; the sentence is rebuilt around it instead, so it does not read as though the
   * operator had written {@code {?}}, and the length bound stops a long identifier-shaped string
   * riding through.
   */
  private static String unsupportedVariable(final String name) {
    return SAFE_VARIABLE_NAME.matcher(name).matches()
        ? "unsupported template variable {" + name + "}"
        : "an unsupported template variable";
  }

  private static IllegalStateException postLogoutRedirectUriError(
      final String registrationId, final String value, final String problem) {
    return new IllegalStateException(
        "Cannot build ClientRegistration '"
            + registrationId
            + "': post-logout-redirect-uri "
            + problem
            + ", but was: "
            + UrlRedaction.redact(value)
            + ". Set camunda.security.authentication.oidc.post-logout-redirect-uri (flat) or"
            + " camunda.security.authentication.providers.oidc."
            + registrationId
            + ".post-logout-redirect-uri.");
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
   * {@code URI} accepts a numeric port that no socket can use, for example {@code :0} and {@code
   * :65536}, and it still reports a host. Such a value therefore satisfies each other check, and it
   * fails only where a component opens a connection. {@link URI#getPort()} reports {@code -1} for a
   * URL without a port, and the default port of the scheme then applies.
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
        + UrlRedaction.redact(value)
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
   * A provider cannot both disable the UserInfo fetch ({@code user-info-enabled=false}, which nulls
   * {@code userInfoUri}) and require it to succeed. Rejecting this combination at startup, rather
   * than letting the flag silently do nothing, mirrors {@link
   * CachingOidcClaimsProvider#forConfiguredMappings}'s fail-fast policy for the analogous
   * config-mismatch.
   */
  private static void requireUserInfoRequiredConsistency(
      final String registrationId, final OidcConfiguration oidc) {
    if (oidc.isUserInfoRequired() && !oidc.isUserInfoEnabled()) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': user-info-required=true has no effect when user-info-enabled=false, because"
              + " login then never attempts the UserInfo call this flag is meant to make"
              + " mandatory. Set user-info-enabled=true (the default) under"
              + " camunda.security.authentication.oidc.* (flat) or"
              + " camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*, or remove user-info-required.");
    }
    // The manual-endpoints path (authorization-uri + token-uri + jwk-set-uri, no issuer-uri) can
    // leave user-info-enabled=true with no user-info-uri configured either. shouldRetrieveUserInfo
    // then returns false, so the flag is inert the same way as the check above, just via a
    // provider that never resolves a UserInfo endpoint at all instead of one that's turned off. The
    // issuer-uri path is not checked here: whether discovery yields a userinfo_endpoint isn't known
    // without the network.
    if (oidc.isUserInfoRequired()
        && !StringUtils.hasText(oidc.getIssuerUri())
        && !StringUtils.hasText(oidc.getUserInfoUri())) {
      throw new IllegalStateException(
          "Cannot build ClientRegistration '"
              + registrationId
              + "': user-info-required=true has no effect because no issuer-uri or user-info-uri"
              + " is configured, so this provider never resolves a UserInfo endpoint to call. Set"
              + " user-info-uri (or issuer-uri) under camunda.security.authentication.oidc.* (flat)"
              + " or camunda.security.authentication.providers.oidc."
              + registrationId
              + ".*, or remove user-info-required.");
    }
  }

  /**
   * A path that is not blank and has no leading '/' gives "{baseUrl}physical-tenants/...", which is
   * not a valid URI. The method rejects such a path immediately, so that the caller gets a clear
   * error. {@link #resolveRedirectUri} examines the expansion of the path for each registration.
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
    // Every no-network check ran in validateWithoutNetwork, over the whole map, before the first
    // registration was built. Repeating the list here let the two copies drift.
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
   * end_session_endpoint}. The audiences key and the {@link
   * FailSoftOidcUserService#USER_INFO_REQUIRED_METADATA_KEY} key are always set, even when
   * false/empty, because both are authoritative by presence; an explicit end-session endpoint wins.
   *
   * <p>The map is fresh per registration — the only reason registrations sharing an issuer cannot
   * see each other's audiences or user-info-required flag.
   */
  private static ClientRegistration mergeProviderMetadata(
      final ClientRegistration built, final OidcConfiguration oidc) {
    final Map<String, Object> merged =
        new LinkedHashMap<>(built.getProviderDetails().getConfigurationMetadata());
    merged.put(
        TokenValidatorFactory.AUDIENCES_METADATA_KEY,
        oidc.getAudiences() != null ? List.copyOf(oidc.getAudiences()) : List.of());
    merged.put(FailSoftOidcUserService.USER_INFO_REQUIRED_METADATA_KEY, oidc.isUserInfoRequired());
    if (StringUtils.hasText(oidc.getEndSessionEndpointUri())) {
      merged.put("end_session_endpoint", oidc.getEndSessionEndpointUri());
    }
    return ClientRegistration.withClientRegistration(built)
        .providerConfigurationMetadata(merged)
        .build();
  }

  /**
   * Resolves the {@code redirect_uri} for a registration. The method uses the first value that
   * applies:
   *
   * <ol>
   *   <li>a scoped path for a per-scope chain, as {@code {baseUrl}<scopedRedirectUriPath>}. The
   *       callback then agrees with the redirection endpoint of that chain, which has a prefix.
   *   <li>a {@code redirect-uri} that the {@link OidcConfiguration} configures. It must expand to
   *       an absolute URL. See {@link #isUsableRedirectUri} and {@link
   *       OidcConfiguration#getRedirectUri()}.
   *   <li>the {@code {baseUrl}/sso-callback} default. It agrees with the redirection endpoint at
   *       {@link OidcRedirectionEndpoint#DEFAULT_PATH}.
   * </ol>
   *
   * <p>With the default, a provider that sets no {@code redirect-uri} can complete the login flow.
   * The former {@code ClientRegistrationFactory} in OC did the same.
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
                + UrlRedaction.redact(scopedRedirectUriPath));
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
                + UrlRedaction.redact(configured)
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
   * Tells if the configured redirect-uri gives a callback that the IdP and this application can
   * both use, in each {@link #sampleRequestShapes request shape} of this registration. The
   * expansion must give an absolute http(s) URL with a host, a port in the TCP range and a path.
   * The URL must have no fragment, because RFC 6749, section 3.1.2, does not permit one. A query is
   * permitted, and the application sends it to the IdP. The path must be a path {@link
   * #isServableByTheDefaultFirewall the default firewall permits}, and the callback must be a
   * callback {@link #callbackMatchesTheRedirectionEndpoint the related redirection endpoint
   * matches}.
   *
   * <p>The check expands the value as {@code DefaultOAuth2AuthorizationRequestResolver} does, with
   * the same builder and the same variable names. It does not model which placeholder gives which
   * value. No rule in this class must therefore stay correct with a Spring upgrade. A placeholder
   * that the resolver cannot expand, an authority that stays incomplete, and a template that is no
   * URL all fail in the expansion itself.
   */
  private boolean isUsableRedirectUri(final String configured, final String registrationId) {
    return sampleRequestShapes(registrationId).stream()
        .allMatch(uriVariables -> isUsableForRequestShape(configured, uriVariables));
  }

  /**
   * Tells if the redirection endpoint that {@link OidcRedirectionEndpoint#resolve} derives from
   * this redirect-uri matches the callback path from the expansion. The two users of the value must
   * agree in this way. The method does not examine routing. The value alone does not tell if a
   * chain mounts the value of this provider, and it does not tell if the {@code securityMatcher} of
   * a chain selects the value for the callback request. The {@code SecurityPathPort} of the host
   * gives both answers.
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
