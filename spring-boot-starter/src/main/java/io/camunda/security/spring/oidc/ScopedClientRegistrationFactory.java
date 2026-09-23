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
 *
 * <p><b>Provider-block validation never blocks startup</b> (see ADR-0027). A provider block that
 * looks wrong — a bad URL, a missing field, an unusable redirect-uri — logs a {@code WARN} naming
 * the provider and the problem, and the application starts regardless. A provider can still fail to
 * build: Spring's own {@link ClientRegistration.Builder#build()} throws for some of the same
 * problems (a blank client-id, for one), and so do {@link
 * org.springframework.security.oauth2.core.ClientAuthenticationMethod}'s constructor and {@link
 * ClientRegistrations#fromIssuerLocation} for a malformed {@code issuer-uri}. Whether that failure
 * is deferred to first use, rather than blocking startup, depends on the caller: {@link
 * LazyClientRegistrationRepository}, {@link ScopedJwtDecoderFactory} and {@link
 * ScopedOidcClaimsProviderFactory} resolve lazily through {@link DeferredOidcResolution}, so one
 * bad provider never takes down another there — but a host calling {@link
 * #createFromProviderMap(Map)}, {@link #createWithoutLoginRoutes(Map)} or {@link
 * #create(AuthenticationConfiguration)} directly, eagerly, from its own {@code @Bean} method still
 * gets that failure at startup. This does not extend to a caller's own arguments, such as {@code
 * scopedRedirectUriPath}: a malformed one is still a programmer error and still throws.
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

  /** {@code LINE SEPARATOR} (U+2028) and {@code PARAGRAPH SEPARATOR} (U+2029). */
  private static final int LINE_SEPARATOR = 0x2028;

  private static final int PARAGRAPH_SEPARATOR = 0x2029;

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
   * Creates one {@link ClientRegistration} for each entry in the provider map, keyed by the map's
   * registrationId. A provider block that looks wrong logs a warning (see {@link
   * #validateWithoutNetwork}) rather than stopping the application.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers) {
    return createFromProviderMap(providers, null);
  }

  /**
   * As {@link #createFromProviderMap(Map)}, but replaces each registration's {@code redirect_uri}
   * with {@code scopedRedirectUriPath} when given. A scoped webapp chain listens at a prefixed path
   * (for example {@code /physical-tenants/{id}/sso-callback}), and the registration's redirect-uri
   * has to agree with it or the IdP calls back to a path the scoped chain never intercepts.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @param scopedRedirectUriPath the path to use as the redirect-uri, for example {@code
   *     /physical-tenants/t1/sso-callback}. If {@code null} or blank, keeps the configured
   *     redirect-uri.
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank and does not start with
   *     '/'
   */
  public List<ClientRegistration> createFromProviderMap(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    return createFromProviderMap(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  /**
   * As {@link #createFromProviderMap(Map)}, for a caller that derives no browser login route from
   * the configuration — token validation on an API chain, or UserInfo augmentation. Neither reads a
   * registration id, a redirect-uri or an end-session endpoint, so those checks are skipped.
   *
   * @param providers map of registrationId to {@link OidcConfiguration}; must not be {@code null}
   * @return an ordered list of {@link ClientRegistration} instances, one per map entry
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
    return buildAll(providers, scopedRedirectUriPath, loginRouteChecks);
  }

  /**
   * Builds a {@link ClientRegistration} per map entry, with no no-network validation of its own.
   * For a caller such as {@link LazyClientRegistrationRepository#findByRegistrationId}, {@link
   * ScopedJwtDecoderFactory} or {@link ScopedOidcClaimsProviderFactory} that already ran {@link
   * #validateWithoutNetwork} (or {@link #validateWithoutLoginRoutes}) once, over the whole provider
   * map, before resolving any one registration lazily: repeating that validation on every retry of
   * a registration that keeps failing to build would re-log the same WARN on every request, unlike
   * a genuine build failure, which {@link DeferredOidcResolution} already rate-limits. Package-
   * private, not a caller-facing "already validated" method of its own — nothing enforces that
   * precondition, so a caller either validates first (most already do, for their own reasons) or
   * accepts building without the diagnostic that validation gives.
   */
  List<ClientRegistration> buildAll(
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
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
   */
  public List<ClientRegistration> create(final AuthenticationConfiguration authentication) {
    return createFromProviderMap(flatten(authentication));
  }

  /**
   * Makes each check that {@link #createFromProviderMap(Map, String)} makes without network access,
   * and builds no registration. A caller that resolves registrations only when it needs them can
   * run this at startup, so a problem is logged where the configuration is, rather than only
   * surfacing on the first request that needs it. A provider block that fails a check is logged,
   * not rejected — see the class Javadoc.
   *
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank and does not start with
   *     '/'
   */
  public void validateWithoutNetwork(
      final Map<String, OidcConfiguration> providers, final String scopedRedirectUriPath) {
    validateWithoutNetwork(providers, scopedRedirectUriPath, LoginRouteChecks.ENFORCED);
  }

  /**
   * As {@link #validateWithoutNetwork}, for a caller that derives no browser login route from the
   * configuration. See {@link #createWithoutLoginRoutes(Map)}.
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
          warnIfBlankRegistrationId(registrationId);
          if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
            warnIfRegistrationIdNotAddressableByTheLoginRoute(registrationId);
          }
          warnIfNoClientId(registrationId, oidc);
          warnIfUnusableClientAuthenticationMethod(registrationId, oidc);
          warnIfUnusableScopes(registrationId, oidc);
          warnIfNotAbsoluteEndpointUrls(registrationId, oidc, loginRouteChecks);
          if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
            // Only a caller mounting the browser login chain mounts the logout handler, which is
            // the
            // sole consumer of this value — the same reasoning that gates end-session-endpoint-uri.
            warnIfPostLogoutRedirectUriUnusable(registrationId, oidc, true);
          }
          warnIfEndpointConfigurationIncomplete(registrationId, oidc);
          resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks);
        });
  }

  /**
   * Tells if the caller mounts the browser login chain. Such a caller derives the login route from
   * the registration id, and the redirection endpoint from the redirect-uri. It also mounts the
   * logout handler, which is the only consumer of the end-session endpoint. The factory makes each
   * of these checks only for such a caller. Package-private so {@link #buildAll}'s other callers
   * can pass it directly.
   */
  enum LoginRouteChecks {
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
    LOG.warn(
        "camunda.security.authentication.oidc.redirect-uri may not expand to a usable callback URL"
            + " for the webapp chain's redirection endpoint (was: {}).",
        UrlRedaction.redact(configured));
  }

  /**
   * Escapes a control character (for example CR or LF) in operator-supplied text to its 4-digit
   * unicode escape form before it reaches a log message, so a registrationId carrying one cannot
   * forge a line in the log it is quoted in — the same treatment {@link UrlRedaction} gives a
   * control character in a URL value, and for the same reason: escaping, not dropping, keeps the
   * value diagnosable. Also escapes the line and paragraph separators {@code
   * isServableByTheDefaultFirewall} already checks for beside {@link Character#isISOControl}, which
   * does not cover them, unlike a regex {@code Cntrl} class, which is ASCII-only and would miss all
   * three. {@code registrationId} is never validated by this class the way a URL value is — a
   * caller can set it to anything — so every place that logs it needs this, not just the checks
   * that reject an unsafe form. Public because callers outside this package (for example {@code
   * ScopedWebappSecurityChainBuilder}) log a raw registrationId of their own too.
   */
  public static String sanitizeForLog(final String value) {
    if (value == null || value.chars().noneMatch(ScopedClientRegistrationFactory::mustBeEscaped)) {
      return value;
    }
    final var escaped = new StringBuilder(value.length());
    value
        .chars()
        .forEach(c -> escaped.append(mustBeEscaped(c) ? String.format("\\u%04x", c) : (char) c));
    return escaped.toString();
  }

  private static boolean mustBeEscaped(final int c) {
    return Character.isISOControl(c) || c == LINE_SEPARATOR || c == PARAGRAPH_SEPARATOR;
  }

  private static void warnIfBlankRegistrationId(final String registrationId) {
    if (!StringUtils.hasText(registrationId)) {
      LOG.warn(
          "OIDC registrationId should be non-blank: set"
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
  private static void warnIfRegistrationIdNotAddressableByTheLoginRoute(
      final String registrationId) {
    if (!isAddressableAsASinglePathSegment(registrationId)) {
      final var safeId = sanitizeForLog(registrationId);
      LOG.warn(
          "OIDC registrationId '{}' is not addressable as a single path segment, so its login"
              + " route (<basePath>/oauth2/authorization/{}) may not resolve to this provider. Set"
              + " camunda.security.authentication.oidc.registration-id (flat block) or rename the"
              + " key under camunda.security.authentication.providers.oidc.<id>.",
          safeId,
          safeId);
    }
  }

  /**
   * Makes the login route in the same way as {@code LoginLinksBuilder}. The method then asks {@link
   * URI} if the id stays one segment in that route, and asks the default firewall if it permits the
   * route. This class therefore does not decide which characters are delimiters or forbidden forms.
   */
  private static boolean isAddressableAsASinglePathSegment(final String registrationId) {
    // A blank/null id already gets its own warning from warnIfBlankRegistrationId; here it is
    // simply not addressable, and never fed to registrationId.equals(...) below.
    if (!StringUtils.hasText(registrationId)) {
      return false;
    }
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
   * A blank client-id makes {@link ClientRegistration.Builder#build()} fail later, when this
   * provider is actually resolved. Warning here surfaces the problem early without stopping the
   * application for it.
   */
  private static void warnIfNoClientId(final String registrationId, final OidcConfiguration oidc) {
    if (!StringUtils.hasText(oidc.getClientId())) {
      final var safeId = sanitizeForLog(registrationId);
      LOG.warn(
          "OIDC provider '{}' has no client-id set. Set"
              + " camunda.security.authentication.oidc.client-id (flat) or"
              + " camunda.security.authentication.providers.oidc.{}.client-id.",
          safeId,
          safeId);
    }
  }

  /** Warns early about a {@link ClientAuthenticationMethod} the build path would also reject. */
  private static void warnIfUnusableClientAuthenticationMethod(
      final String registrationId, final OidcConfiguration oidc) {
    try {
      new ClientAuthenticationMethod(oidc.getClientAuthenticationMethod());
    } catch (final IllegalArgumentException rejected) {
      final var safeId = sanitizeForLog(registrationId);
      LOG.warn(
          "OIDC provider '{}' has no usable client-authentication-method. Set"
              + " camunda.security.authentication.oidc.client-authentication-method (flat) or"
              + " camunda.security.authentication.providers.oidc.{}.client-authentication-method.",
          safeId,
          safeId,
          rejected);
    }
  }

  /**
   * Warns early about a scope RFC 6749 does not permit in a scope token — most often a space,
   * meaning one {@code scope} entry holds a space-separated list instead of one value per entry.
   */
  private static void warnIfUnusableScopes(
      final String registrationId, final OidcConfiguration oidc) {
    if (oidc.getScope() == null) {
      return;
    }
    try {
      // Stand-in registrationId/clientId, the same way resolveRedirectUri's probeId stands in for
      // an unusable one: build() validates both before it validates scopes, so a blank client-id
      // (already its own, separate warning) must not make this probe misreport itself as a scope
      // problem.
      ClientRegistration.withRegistrationId(OidcConfiguration.DEFAULT_REGISTRATION_ID)
          .clientId("probe-client")
          .redirectUri(BASE_URL_PLACEHOLDER)
          .authorizationUri("https://probe.invalid/auth")
          .tokenUri("https://probe.invalid/token")
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .scope(oidc.getScope())
          .build();
    } catch (final IllegalArgumentException rejected) {
      // Not rejected itself: Spring's own message quotes the configured scope verbatim, and a
      // scope containing CR/LF could then forge a line in this log despite registrationId being
      // sanitized. The warning below already says everything actionable without it.
      final var safeId = sanitizeForLog(registrationId);
      LOG.warn(
          "OIDC provider '{}' has an unusable scope. A scope is one entry per value, not a"
              + " space-separated list. Set them under camunda.security.authentication.oidc.scope"
              + " (flat) or camunda.security.authentication.providers.oidc.{}.scope.",
          safeId,
          safeId);
    }
  }

  /**
   * Each endpoint in a provider block is an address to which the application sends requests. A
   * check of these addresses needs no network, so a typo is logged here rather than only surfacing
   * on the first related request, much later. Two endpoints are exempt where nothing dereferences
   * them: a {@code user-info-uri} that the build path discards, and the end-session endpoint of a
   * caller that mounts no login chain.
   */
  private static void warnIfNotAbsoluteEndpointUrls(
      final String registrationId,
      final OidcConfiguration oidc,
      final LoginRouteChecks loginRouteChecks) {
    warnIfNotAbsoluteHttpUrl(registrationId, "issuer-uri", oidc.getIssuerUri());
    warnIfNotAbsoluteHttpUrl(registrationId, "authorization-uri", oidc.getAuthorizationUri());
    warnIfNotAbsoluteHttpUrl(registrationId, "token-uri", oidc.getTokenUri());
    warnIfNotAbsoluteHttpUrl(registrationId, "jwk-set-uri", oidc.getJwkSetUri());
    if (oidc.isUserInfoEnabled()) {
      // A disabled provider has its userInfoUri nulled on the build path, so a stale value there is
      // never requested — validating it would fail a deployment that works today.
      warnIfNotAbsoluteHttpUrl(registrationId, "user-info-uri", oidc.getUserInfoUri());
    }
    if (loginRouteChecks == LoginRouteChecks.ENFORCED) {
      // CamundaOidcLogoutSuccessHandler is the only consumer, and it exists on the webapp login
      // chain. A caller that mounts no such chain never dereferences the value.
      warnIfNotAbsoluteHttpUrl(
          registrationId, "end-session-endpoint-uri", oidc.getEndSessionEndpointUri());
    }
    if (oidc.getAdditionalJwkSetUris() != null) {
      oidc.getAdditionalJwkSetUris()
          .forEach(uri -> warnIfNotAbsoluteHttpUrl(registrationId, "additional-jwk-set-uris", uri));
    }
  }

  /**
   * Warns about a {@code post-logout-redirect-uri} that cannot work, instead of letting logout fail
   * on it later. Three accepted shapes: a path starting with {@code /}, an absolute URL, or a URI
   * template that still resolves to an absolute URL once Spring expands it. See ADR-0026.
   *
   * <p>This narrower entry point exists for a consumer that can reach a provider map the factory
   * never built: a host that replaces the {@code ClientRegistrationRepository} bean bypasses {@link
   * #createFromProviderMap}, but the logout handler still reads its configuration from here.
   *
   * @param providers the provider configurations keyed by registration id; must not be {@code null}
   */
  public void validatePostLogoutRedirectUris(final Map<String, OidcConfiguration> providers) {
    Objects.requireNonNull(providers, "providers must not be null");
    providers.forEach(
        (registrationId, oidc) -> warnIfPostLogoutRedirectUriUnusable(registrationId, oidc, true));
  }

  /**
   * Whether the provider's configured post-logout-redirect-uri, if any, is usable. Warns nothing:
   * {@link #validateWithoutNetwork} and {@link #validatePostLogoutRedirectUris} already warn about
   * the same provider, over the whole map, before a caller such as {@code
   * ScopedWebappSecurityChainBuilder} composes the value it actually sends. That caller uses this
   * to fall back instead of handing Spring a value that would only fail later, at logout.
   */
  public boolean isPostLogoutRedirectUriUsable(
      final String registrationId, final OidcConfiguration oidc) {
    return warnIfPostLogoutRedirectUriUnusable(registrationId, oidc, false);
  }

  /**
   * Returns whether the value is usable; warns about it only when {@code warnIfUnusable} is set.
   */
  private boolean warnIfPostLogoutRedirectUriUnusable(
      final String registrationId, final OidcConfiguration oidc, final boolean warnIfUnusable) {
    final var configured = oidc.getPostLogoutRedirectUri();
    if (!StringUtils.hasText(configured)) {
      return true;
    }
    final var value = configured.trim();
    // Covers CR and LF, which would otherwise forge a line in the log this error is written to,
    // and the rest of the control characters, which no component can serve.
    if (value.chars().anyMatch(Character::isISOControl)) {
      warnPostLogoutRedirectUri(
          registrationId, value, "must not contain control characters", warnIfUnusable);
      return false;
    }
    // OpenID Connect RP-Initiated Logout 1.0 §2 gives post_logout_redirect_uri no fragment, so an
    // OP has no reason to accept one.
    if (value.indexOf('#') >= 0) {
      warnPostLogoutRedirectUri(
          registrationId, value, "must not contain a fragment ('#')", warnIfUnusable);
      return false;
    }
    if (!isExpandableTemplate(registrationId, value, warnIfUnusable)) {
      return false;
    }
    if (!value.startsWith("/") && !isUsableAbsoluteForm(registrationId, value, warnIfUnusable)) {
      return false;
    }
    // sampleRequestShape expands {registrationId} through Map.of, which rejects a null value; a
    // blank/null registrationId already gets its own warning from warnIfBlankRegistrationId, so
    // template expansion here only needs a stand-in id, not the diagnostic name.
    final var probeId =
        StringUtils.hasText(registrationId)
            ? registrationId
            : OidcConfiguration.DEFAULT_REGISTRATION_ID;
    if (!isUsablePostLogoutRedirectUri(value, probeId)) {
      warnPostLogoutRedirectUri(
          registrationId,
          value,
          "must expand to an absolute http(s) URL with a host, a port in 1-65535 if it names one,"
              + " and no fragment",
          warnIfUnusable);
      return false;
    }
    return true;
  }

  /** The checks that only a non-path value can fail. Returns false once one of them has warned. */
  private static boolean isUsableAbsoluteForm(
      final String registrationId, final String value, final boolean warnIfUnusable) {
    if (!continuesWithAPath(value)) {
      warnPostLogoutRedirectUri(
          registrationId,
          value,
          "must continue with a path after {baseUrl}, which already carries the scheme, host and"
              + " port",
          warnIfUnusable);
      return false;
    }
    if (!resolvesToAnAbsoluteUrl(value)) {
      warnPostLogoutRedirectUri(
          registrationId,
          value,
          "must be an absolute URL, a path starting with '/', or a template that still resolves to"
              + " an absolute URL (starting with {baseUrl}, or carrying an explicit scheme and a"
              + " host, such as {baseScheme}://{baseHost})",
          warnIfUnusable);
      return false;
    }
    return isParseableAbsoluteUrl(registrationId, value, warnIfUnusable);
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
  private static boolean isExpandableTemplate(
      final String registrationId, final String value, final boolean warnIfUnusable) {
    int openAt = -1;
    for (int i = 0; i < value.length(); i++) {
      final char c = value.charAt(i);
      if (c == '{') {
        if (openAt >= 0) {
          warnPostLogoutRedirectUri(registrationId, value, "contains a nested '{'", warnIfUnusable);
          return false;
        }
        openAt = i;
      } else if (c == '}') {
        if (openAt < 0) {
          warnPostLogoutRedirectUri(
              registrationId, value, "contains an unmatched '}'", warnIfUnusable);
          return false;
        }
        final var name = value.substring(openAt + 1, i);
        if (!POST_LOGOUT_TEMPLATE_VARIABLES.contains(name)) {
          warnPostLogoutRedirectUri(
              registrationId,
              value,
              "uses "
                  + unsupportedVariable(name)
                  + "; supported variables are "
                  + POST_LOGOUT_TEMPLATE_VARIABLES,
              warnIfUnusable);
          return false;
        }
        openAt = -1;
      }
    }
    if (openAt >= 0) {
      warnPostLogoutRedirectUri(registrationId, value, "contains an unclosed '{'", warnIfUnusable);
      return false;
    }
    return true;
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
  private static boolean isParseableAbsoluteUrl(
      final String registrationId, final String value, final boolean warnIfUnusable) {
    if (value.startsWith(BASE_URL_PLACEHOLDER)) {
      return true;
    }
    final var schemeEnd = value.indexOf("://");
    final var scheme = value.substring(0, schemeEnd);
    final var authority = authorityOf(value, schemeEnd + 3);
    if (authority.indexOf('{') >= 0) {
      return true;
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
      warnPostLogoutRedirectUri(
          registrationId, value, "is not a valid URI: " + malformed.getReason(), warnIfUnusable);
      return false;
    }
    if (!parsed.isAbsolute() || !StringUtils.hasText(parsed.getHost())) {
      warnPostLogoutRedirectUri(
          registrationId, value, "is missing a scheme or a host", warnIfUnusable);
      return false;
    }
    if (!namesAPortInTcpRange(parsed)) {
      warnPostLogoutRedirectUri(
          registrationId, value, "must name a port in 1-65535 if it names one", warnIfUnusable);
      return false;
    }
    return true;
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

  private static void warnPostLogoutRedirectUri(
      final String registrationId,
      final String value,
      final String problem,
      final boolean warnIfUnusable) {
    if (!warnIfUnusable) {
      return;
    }
    final var safeId = sanitizeForLog(registrationId);
    LOG.warn(
        "OIDC provider '{}' has an unusable post-logout-redirect-uri ({}, but was: {}). Set"
            + " camunda.security.authentication.oidc.post-logout-redirect-uri (flat) or"
            + " camunda.security.authentication.providers.oidc.{}.post-logout-redirect-uri.",
        safeId,
        problem,
        UrlRedaction.redact(value),
        safeId);
  }

  private static void warnIfNotAbsoluteHttpUrl(
      final String registrationId, final String property, final String value) {
    if (!StringUtils.hasText(value)) {
      return;
    }
    final URI parsed;
    try {
      parsed = new URI(value);
    } catch (final URISyntaxException malformed) {
      // getReason(), not the exception itself: its message/toString echoes the raw, unredacted
      // value, which would leak a credential embedded in it right past the redaction below.
      LOG.warn(
          endpointUrlError(registrationId, property, value) + " (" + malformed.getReason() + ")");
      return;
    }
    final var scheme = parsed.getScheme();
    if (!parsed.isAbsolute()
        || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
        || !StringUtils.hasText(parsed.getHost())
        || !namesAPortInTcpRange(parsed)) {
      LOG.warn(endpointUrlError(registrationId, property, value));
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
    final var safeId = sanitizeForLog(registrationId);
    return "OIDC provider '"
        + safeId
        + "' has an unusable "
        + property
        + ": it must be an absolute http(s) URL with a host and, if it names a port, one in"
        + " 1-65535, but was: "
        + UrlRedaction.redact(value)
        + ". Set camunda.security.authentication.oidc."
        + property
        + " (flat) or camunda.security.authentication.providers.oidc."
        + safeId
        + "."
        + property
        + ".";
  }

  private static void warnIfEndpointConfigurationIncomplete(
      final String registrationId, final OidcConfiguration oidc) {
    if (StringUtils.hasText(oidc.getIssuerUri())
        || (StringUtils.hasText(oidc.getAuthorizationUri())
            && StringUtils.hasText(oidc.getTokenUri())
            && StringUtils.hasText(oidc.getJwkSetUri()))) {
      return;
    }
    final var safeId = sanitizeForLog(registrationId);
    LOG.warn(
        "OIDC provider '{}' is incomplete: set issuer-uri, or all of authorization-uri, token-uri"
            + " and jwk-set-uri, under camunda.security.authentication.oidc.* (flat) or"
            + " camunda.security.authentication.providers.oidc.{}.*.",
        safeId,
        safeId);
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
    // registration was built. Repeating the list here let the two copies drift; warnIfUnusable is
    // false below for the same reason — that pass already warned about this same provider.
    final var redirectUri =
        resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks, false);
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
          UrlRedaction.redact(issuerUri),
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
   * The former {@code ClientRegistrationFactory} in OC did the same. A configured value that does
   * not expand to a usable callback URL is used as-is, with a WARN naming the provider and the
   * problem, rather than rejected.
   */
  private String resolveRedirectUri(
      final String registrationId,
      final OidcConfiguration oidc,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks) {
    return resolveRedirectUri(registrationId, oidc, scopedRedirectUriPath, loginRouteChecks, true);
  }

  /**
   * As {@link #resolveRedirectUri(String, OidcConfiguration, String, LoginRouteChecks)}, but warns
   * only when {@code warnIfUnusable} is set. {@link #buildClientRegistration} needs the resolved
   * value itself, not a second diagnostic: {@link #validateWithoutNetwork} already warned about
   * this same provider, over the whole map, before any registration was built. The usability check
   * itself, and its fallback to the default, still apply either way: {@link
   * OidcRedirectionEndpoint#resolve} makes the same fallback for the unscoped chain's redirection
   * endpoint, over the same flat {@code redirect-uri}, so the two consumers of the value must agree
   * on it, or the chain listens at the default path while the IdP is told to call back elsewhere.
   */
  private String resolveRedirectUri(
      final String registrationId,
      final OidcConfiguration oidc,
      final String scopedRedirectUriPath,
      final LoginRouteChecks loginRouteChecks,
      final boolean warnIfUnusable) {
    final var checkCallback = loginRouteChecks == LoginRouteChecks.ENFORCED;
    // sampleRequestShape expands {registrationId} through Map.of, which rejects a null value; a
    // blank/null registrationId already gets its own warning from warnIfBlankRegistrationId, so
    // template expansion here only needs a stand-in id, not the diagnostic name.
    final var probeId =
        StringUtils.hasText(registrationId)
            ? registrationId
            : OidcConfiguration.DEFAULT_REGISTRATION_ID;
    if (StringUtils.hasText(scopedRedirectUriPath)) {
      final var scoped = BASE_URL_PLACEHOLDER + scopedRedirectUriPath;
      if (checkCallback && warnIfUnusable && !isUsableRedirectUri(scoped, probeId)) {
        LOG.warn(
            "The scoped redirect-uri path '{}' for OIDC provider '{}' may not yield a callback"
                + " this application can serve — the scoped chain's redirection endpoint may not"
                + " match it once expanded.",
            UrlRedaction.redact(scopedRedirectUriPath),
            sanitizeForLog(registrationId));
      }
      return scoped;
    }
    if (StringUtils.hasText(oidc.getRedirectUri())) {
      final String configured = oidc.getRedirectUri();
      if (checkCallback && !isUsableRedirectUri(configured, probeId)) {
        if (warnIfUnusable) {
          final var safeId = sanitizeForLog(registrationId);
          LOG.warn(
              "OIDC provider '{}' has a redirect-uri that may not expand to a usable callback URL"
                  + " (was: {}); the {baseUrl}/sso-callback default is used instead. Spring expands"
                  + " {baseUrl}, {baseScheme}, {baseHost}, {basePort}, {basePath},"
                  + " {registrationId} and {action} per request. Set"
                  + " camunda.security.authentication.oidc.redirect-uri (flat) or"
                  + " camunda.security.authentication.providers.oidc.{}.redirect-uri.",
              safeId,
              UrlRedaction.redact(configured),
              safeId);
        }
        return BASE_URL_PLACEHOLDER + OidcRedirectionEndpoint.DEFAULT_PATH;
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
    // resolve no longer throws (it falls back to defaultPath with a WARN instead), so there is no
    // exception left to catch here.
    final var endpointPath =
        OidcRedirectionEndpoint.resolve(
            configured, contextPath, OidcRedirectionEndpoint.DEFAULT_PATH);
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
    // warnIfEndpointConfigurationIncomplete already ran in validateWithoutNetwork, over the whole
    // map, before createFromProviderMap called this method — see buildClientRegistration.
    final boolean hasIssuer = StringUtils.hasText(oidc.getIssuerUri());
    final ClientRegistration.Builder builder =
        hasIssuer
            ? discoveredBuilder(oidc.getIssuerUri()).registrationId(registrationId)
            : ClientRegistration.withRegistrationId(registrationId);

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
