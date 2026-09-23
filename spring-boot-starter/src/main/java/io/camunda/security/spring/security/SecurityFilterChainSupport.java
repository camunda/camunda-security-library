/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGOUT_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.model.config.headers.HeaderConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import io.camunda.security.spring.csrf.CsrfProtectionRequestMatcher;
import io.camunda.security.spring.scope.BasePaths;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.server.PathContainer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPatternParser;

/** Shared helpers for assembling CSL security filter chains. */
public final class SecurityFilterChainSupport {

  private SecurityFilterChainSupport() {}

  /**
   * Computes the set of paths exempt from CSRF protection. The unprefixed {@code /logout} constant
   * is always included (primary/global chain behaviour) — logging a session out carries no
   * meaningful impact if forged cross-site, unlike logging one in. {@code /login} is deliberately
   * <b>not</b> included here: see {@link #csrfEnforcedPaths} and
   * camunda/security-testing-findings#281. When {@code cookiePath} is non-null and non-blank it
   * identifies a per-scope basePath (e.g. {@code /physical-tenants/t1}); in that case the prefixed
   * variant {@code basePath/logout} is also added so that CSRF exemption on scoped chains is
   * consistent with the primary chain. Trailing slashes on {@code cookiePath} are stripped before
   * concatenation to avoid double-slash paths.
   *
   * <p>Package-private for unit testing.
   */
  static Set<String> csrfAllowedPaths(
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final String cookiePath) {
    final var allowedPaths = new HashSet<String>();
    allowedPaths.addAll(pathPort.unprotectedPaths());
    allowedPaths.addAll(pathPort.unprotectedApiPaths());
    allowedPaths.addAll(csrfLogoutPaths(cookiePath));
    allowedPaths.addAll(properties.getCsrf().getIgnoredPathPatterns());
    return allowedPaths;
  }

  /**
   * Computes the logout endpoint(s) exempt from CSRF protection for the given scope: the unprefixed
   * {@code /logout} constant, plus the {@code cookiePath}-prefixed variant when {@code cookiePath}
   * identifies a per-scope basePath (e.g. {@code /physical-tenants/t1}).
   *
   * <p>Package-private for unit testing.
   */
  static Set<String> csrfLogoutPaths(final String cookiePath) {
    final var logoutPaths = new HashSet<String>();
    addScopedPath(logoutPaths, LOGOUT_URL, cookiePath);
    return logoutPaths;
  }

  /**
   * Adds {@code suffix} (e.g. {@code /login}/{@code /logout}) to {@code target}, and, when {@code
   * cookiePath} identifies a per-scope basePath, also adds the {@code cookiePath}-prefixed variant.
   * Trailing slashes on {@code cookiePath} are stripped before concatenation to avoid double-slash
   * paths.
   */
  private static void addScopedPath(
      final Set<String> target, final String suffix, final String cookiePath) {
    target.add(suffix);
    if (cookiePath != null && !cookiePath.isBlank()) {
      final var base = BasePaths.normalize(cookiePath, "cookiePath");
      target.add(base + suffix);
    }
  }

  /**
   * Computes the set of paths that require a valid CSRF token unconditionally, even on a browser
   * that holds no session yet. Only the login endpoint is enforced this way: it is the one
   * state-changing, unauthenticated endpoint every webapp chain exposes, and skipping CSRF there
   * lets a cross-site {@code POST /login} silently replace a victim's already-authenticated session
   * with an attacker-controlled one (camunda/security-testing-findings#281). The generic "protect
   * once a session exists" rule in {@link
   * io.camunda.security.spring.csrf.CsrfProtectionRequestMatcher} is not enough here, because the
   * attack's whole premise is that the victim's browser already has a session by the time the
   * forged request lands.
   *
   * <p>The CSRF token itself is still obtainable by an anonymous visitor: {@link
   * #csrfTokenResponseHeaderFilter()} issues one on {@code GET} to the login endpoint regardless of
   * authentication state, via the cookie-backed, session-independent double-submit token
   * repository.
   *
   * <p>Package-private for unit testing.
   */
  static Set<String> csrfEnforcedPaths(final String cookiePath) {
    final var enforcedPaths = new HashSet<String>();
    addScopedPath(enforcedPaths, LOGIN_URL, cookiePath);
    return enforcedPaths;
  }

  /**
   * Fails fast if any of {@code unprotectedPaths} would also match one of {@code enforcedPaths}
   * (the login endpoint, unprefixed or under a scoped {@code basePath}). {@link
   * BaseSecurityConfiguration}'s unprotected-paths chain is always checked first by Spring's {@code
   * FilterChainProxy} and unconditionally disables CSRF for whatever it matches, so an overlapping
   * declaration would route the login request there instead of the webapp chain that actually
   * enforces CSRF on it — silently defeating the unconditional login-CSRF protection ADR-0027
   * requires (camunda/security-testing-findings#281), for that one scope. Called once per chain
   * build (primary and each scope) precisely because a scope's login path is only known once its
   * {@code cookiePath}/{@code basePath} is resolved — {@code unprotectedPaths()} is a single,
   * unscoped set the host declares once, and a scope's own base path is arbitrary, host-decided,
   * and not enumerable up front.
   */
  static void rejectUnprotectedPathOverlap(
      final Set<String> unprotectedPaths, final Set<String> enforcedPaths) {
    for (final var enforcedPath : enforcedPaths) {
      final var enforcedPathContainer = PathContainer.parsePath(enforcedPath);
      final var offendingPattern =
          unprotectedPaths.stream()
              .filter(
                  pattern ->
                      PathPatternParser.defaultInstance
                          .parse(pattern)
                          .matches(enforcedPathContainer))
              .findFirst();
      if (offendingPattern.isPresent()) {
        throw new IllegalStateException(
            "SecurityPathPort#unprotectedPaths() declares '"
                + offendingPattern.get()
                + "', which matches the CSRF-enforced path '"
                + enforcedPath
                + "'. The login endpoint requires a valid CSRF token unconditionally"
                + " (camunda/security-testing-findings#281) and must not be declared as, or"
                + " overlap, an unprotected path — remove or narrow this pattern.");
      }
    }
  }

  public static CookieCsrfTokenRepository cookieCsrfTokenRepository(
      final CamundaSecurityLibraryProperties properties) {
    return buildCookieCsrfTokenRepository(properties, null, X_CSRF_TOKEN);
  }

  public static CookieCsrfTokenRepository cookieCsrfTokenRepository(
      final CamundaSecurityLibraryProperties properties, final String cookiePath) {
    return buildCookieCsrfTokenRepository(properties, resolveCookiePath(cookiePath), X_CSRF_TOKEN);
  }

  public static CookieCsrfTokenRepository cookieCsrfTokenRepository(
      final CamundaSecurityLibraryProperties properties,
      final String cookiePath,
      final String cookieName) {
    return buildCookieCsrfTokenRepository(properties, resolveCookiePath(cookiePath), cookieName);
  }

  private static CookieCsrfTokenRepository buildCookieCsrfTokenRepository(
      final CamundaSecurityLibraryProperties properties,
      final String resolvedCookiePath,
      final String cookieName) {
    Objects.requireNonNull(cookieName, "cookieName must not be null");
    if (cookieName.isBlank()) {
      throw new IllegalArgumentException("cookieName must not be blank");
    }
    final CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();
    repository.setHeaderName(X_CSRF_TOKEN);
    repository.setCookieName(cookieName);
    final boolean httpOnly = properties.getCsrf().isCookieHttpOnly();
    repository.setCookieCustomizer(builder -> builder.httpOnly(httpOnly));
    if (resolvedCookiePath != null) {
      repository.setCookiePath(resolvedCookiePath);
    }
    return repository;
  }

  /**
   * Normalizes a raw cookie/base path value to a resolved path string, or {@code null} when the
   * input is null or blank. A root base path that normalizes to {@code ""} is mapped to {@code "/"}
   * because a cookie {@code Path} attribute cannot be the empty string.
   */
  private static String resolveCookiePath(final String cookiePath) {
    if (cookiePath == null || cookiePath.isBlank()) {
      return null;
    }
    final String normalized = BasePaths.normalize(cookiePath, "cookiePath");
    return normalized.isEmpty() ? "/" : normalized;
  }

  /**
   * Applies CSRF configuration to a webapp/API filter chain. When CSRF is enabled, configures a
   * cookie-backed token repository with a {@link CsrfProtectionRequestMatcher} and adds a response
   * header filter that includes the CSRF token on authenticated GET/login responses. When disabled,
   * CSRF protection is turned off entirely.
   */
  public static void applyCsrfConfiguration(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    applyCsrfConfiguration(http, properties, pathPort, null, X_CSRF_TOKEN);
  }

  public static void applyCsrfConfiguration(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final String cookiePath)
      throws Exception {
    applyCsrfConfiguration(http, properties, pathPort, cookiePath, X_CSRF_TOKEN);
  }

  public static void applyCsrfConfiguration(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final String cookiePath,
      final String csrfCookieName)
      throws Exception {
    if (!properties.getCsrf().isEnabled()) {
      http.csrf(AbstractHttpConfigurer::disable);
      return;
    }

    final var allowedPaths = csrfAllowedPaths(properties, pathPort, cookiePath);
    final var enforcedPaths = csrfEnforcedPaths(cookiePath);
    rejectUnprotectedPathOverlap(pathPort.unprotectedPaths(), enforcedPaths);

    final String resolvedCookiePath = resolveCookiePath(cookiePath);
    final CookieCsrfTokenRepository repo =
        buildCookieCsrfTokenRepository(properties, resolvedCookiePath, csrfCookieName);
    final CsrfTokenRepository csrfTokenRepository =
        (resolvedCookiePath != null)
            ? new ContextPathScopedCsrfTokenRepository(repo, resolvedCookiePath)
            : repo;
    http.csrf(
        csrf ->
            csrf.csrfTokenRepository(csrfTokenRepository)
                .requireCsrfProtectionMatcher(
                    new CsrfProtectionRequestMatcher(allowedPaths, enforcedPaths)));
    http.addFilterAfter(csrfTokenResponseHeaderFilter(cookiePath), CsrfFilter.class);
  }

  /**
   * Adds the filter supplied by {@code provider} after {@code afterFilter} in the chain when the
   * provider has a bean. No-op when the provider is empty, so chain configurations can opt-in to
   * library-supplied filters without hard-wiring the dependency.
   */
  public static <F extends Filter> void addFilterAfterIfAvailable(
      final HttpSecurity http,
      final ObjectProvider<F> provider,
      final Class<? extends Filter> afterFilter) {
    provider.ifAvailable(filter -> http.addFilterAfter(filter, afterFilter));
  }

  /**
   * Configures CORS on the given filter chain using the provided {@link CorsConfigurationSource}.
   * When the source is the CSL no-op default ({@link NoOpCorsConfigurationSource}), CORS is
   * explicitly disabled — preserving the previous always-disabled behaviour. Any host-provided
   * source is always honoured, including a {@link
   * org.springframework.web.cors.UrlBasedCorsConfigurationSource} that starts empty and is
   * populated later via config refresh.
   */
  public static void applyCorsConfiguration(
      final HttpSecurity http, final CorsConfigurationSource corsSource) throws Exception {
    if (corsSource instanceof NoOpCorsConfigurationSource) {
      http.cors(AbstractHttpConfigurer::disable);
    } else {
      http.cors(cors -> cors.configurationSource(corsSource));
    }
  }

  /**
   * Applies every registered {@link HttpsRedirectCustomizer} bean to the given filter chain, in
   * {@link org.springframework.core.annotation.Order} order. When no bean is registered this is a
   * no-op, so CSL's default is no HTTP→HTTPS redirect.
   */
  public static void applyHttpsRedirectCustomizers(
      final HttpSecurity http,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers)
      throws Exception {
    for (final var customizer : httpsRedirectCustomizers.orderedStream().toList()) {
      customizer.customize(http);
    }
  }

  /**
   * Applies every registered {@link SecurityHeadersCustomizer} bean to the given filter chain, in
   * {@link org.springframework.core.annotation.Order} order. When no bean is registered this is a
   * no-op, so CSL's static, property-driven header configuration (see {@link #setupSecureHeaders})
   * is unaffected. See ADR-0016.
   */
  public static void applySecurityHeadersCustomizers(
      final HttpSecurity http,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers)
      throws Exception {
    for (final var customizer : securityHeadersCustomizers.orderedStream().toList()) {
      customizer.customize(http);
    }
  }

  /**
   * Filter that adds the CSRF token to the response header for authenticated GET requests, and for
   * any request to the login endpoint regardless of authentication state. Browser-based clients
   * read the token from the response header (or the readable CSRF cookie the same repository sets)
   * and include it on subsequent state-changing requests.
   *
   * <p>The login endpoint is special-cased: {@code buildBasicWebappChain}/{@code
   * buildOidcWebappChain} both call {@code .anonymous(AbstractHttpConfigurer::disable)}, so an
   * unauthenticated visitor has no {@code Authentication} at all (not even an anonymous one) to
   * gate on. Since {@code POST /login} now requires a valid CSRF token unconditionally (see {@link
   * SecurityFilterChainSupport#csrfEnforcedPaths}), a first-time, anonymous {@code GET} of the
   * login page must still be able to obtain one — otherwise no legitimate login could ever succeed.
   * Handing an anonymous visitor a CSRF token is safe: the token has no meaning on its own, and
   * revealing it to whoever will submit the login form next is the intended behaviour of the
   * double-submit pattern this repository implements.
   *
   * <p>The header must be written <b>before</b> dispatching the chain. {@link
   * HttpServletResponse#setHeader} is a no-op once the response is committed, and any downstream
   * filter that flushes the response buffer during chain processing — gzip compression, large
   * bodies — silently strips a post-chain write. The {@link CsrfToken} request attribute is
   * populated by the upstream {@code CsrfFilter} (we are registered via {@code addFilterAfter(_,
   * CsrfFilter.class)}), so it is available at filter entry.
   *
   * <p>Login/logout detection is scoped to this chain's {@code cookiePath} (unprefixed for the
   * primary chain), matched via {@link
   * io.camunda.security.spring.csrf.CsrfProtectionRequestMatcher#buildPathsMatcher} against the
   * same path sets {@link #csrfEnforcedPaths} and {@link #csrfLogoutPaths} compute for CSRF
   * enforcement/exemption on this scope, rather than by an unscoped substring check.
   */
  public static OncePerRequestFilter csrfTokenResponseHeaderFilter() {
    return csrfTokenResponseHeaderFilter(null);
  }

  public static OncePerRequestFilter csrfTokenResponseHeaderFilter(final String cookiePath) {
    final RequestMatcher loginMatcher =
        CsrfProtectionRequestMatcher.buildPathsMatcher(csrfEnforcedPaths(cookiePath));
    final RequestMatcher logoutMatcher =
        CsrfProtectionRequestMatcher.buildPathsMatcher(csrfLogoutPaths(cookiePath));
    return new OncePerRequestFilter() {
      @Override
      protected void doFilterInternal(
          final HttpServletRequest request,
          final HttpServletResponse response,
          final FilterChain filterChain)
          throws ServletException, IOException {
        writeCsrfTokenHeaderIfApplicable(request, response, loginMatcher, logoutMatcher);
        filterChain.doFilter(request, response);
      }
    };
  }

  private static void writeCsrfTokenHeaderIfApplicable(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final RequestMatcher loginMatcher,
      final RequestMatcher logoutMatcher) {
    if (logoutMatcher.matches(request)) {
      return;
    }
    final boolean isLogin = loginMatcher.matches(request);
    final boolean isGetOrLogin = "GET".equalsIgnoreCase(request.getMethod()) || isLogin;
    if (!isGetOrLogin) {
      return;
    }
    if (!isLogin) {
      // Every other GET still requires an authenticated principal: the login endpoint is the only
      // place an anonymous visitor is meant to receive a token, since it is the only
      // unauthenticated
      // endpoint a legitimate client must POST to (see csrfTokenResponseHeaderFilter() javadoc).
      final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth == null || !auth.isAuthenticated()) {
        return;
      }
    }
    final CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    if (token != null) {
      response.setHeader(X_CSRF_TOKEN, token.getToken());
    }
  }

  /**
   * Configures HTTP security response headers from {@link HeaderConfiguration}. Each header can be
   * individually enabled/disabled and customized via {@code camunda.security.http-headers.*}.
   */
  public static void setupSecureHeaders(
      final HttpSecurity http, final HeaderConfiguration headerConfig) throws Exception {
    http.headers(
        headers -> {
          if (headerConfig.getContentTypeOptions().isDisabled()) {
            headers.contentTypeOptions(c -> c.disable());
          }

          if (headerConfig.getCacheControl().isDisabled()) {
            headers.cacheControl(c -> c.disable());
          }

          final var hsts = headerConfig.getHsts();
          if (hsts.isDisabled()) {
            headers.httpStrictTransportSecurity(h -> h.disable());
          } else {
            headers.httpStrictTransportSecurity(
                h ->
                    h.includeSubDomains(hsts.isIncludeSubDomains())
                        .maxAgeInSeconds(hsts.getMaxAgeInSeconds())
                        .preload(hsts.isPreload()));
          }

          final var frame = headerConfig.getFrameOptions();
          if (frame.disabled()) {
            headers.frameOptions(f -> f.disable());
          } else {
            switch (frame.getMode()) {
              case DENY -> headers.frameOptions(f -> f.deny());
              case SAMEORIGIN -> headers.frameOptions(f -> f.sameOrigin());
              default ->
                  throw new IllegalStateException(
                      "Unhandled frame option mode: " + frame.getMode());
            }
          }

          final var csp = headerConfig.getContentSecurityPolicy();
          if (csp.isEnabled()) {
            final var policy = csp.resolvePolicy();
            if (policy != null) {
              if (csp.isReportOnly()) {
                headers.contentSecurityPolicy(c -> c.reportOnly().policyDirectives(policy));
              } else {
                headers.contentSecurityPolicy(c -> c.policyDirectives(policy));
              }
            }
          }

          headers.referrerPolicy(
              rp ->
                  rp.policy(
                      ReferrerPolicyHeaderWriter.ReferrerPolicy.valueOf(
                          headerConfig.getReferrerPolicy().getValue().name())));

          final var permissionsPolicyValue = headerConfig.getPermissionsPolicy().getValue();
          if (permissionsPolicyValue != null && !permissionsPolicyValue.isBlank()) {
            headers.permissionsPolicyHeader(pp -> pp.policy(permissionsPolicyValue));
          }

          headers.crossOriginOpenerPolicy(
              coop ->
                  coop.policy(
                      CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.valueOf(
                          headerConfig.getCrossOriginOpenerPolicy().getValue().name())));

          headers.crossOriginEmbedderPolicy(
              coep ->
                  coep.policy(
                      CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.valueOf(
                          headerConfig.getCrossOriginEmbedderPolicy().getValue().name())));

          headers.crossOriginResourcePolicy(
              corp ->
                  corp.policy(
                      CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.valueOf(
                          headerConfig.getCrossOriginResourcePolicy().getValue().name())));
        });
  }
}
