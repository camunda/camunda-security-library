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
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGOUT_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.OIDC_REGISTRATION_ID;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.filter.OidcRedirectDiagnosticsFilter;
import io.camunda.security.spring.filter.SessionHeartbeatFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler;
import io.camunda.security.spring.oidc.CamundaOidcAuthorizationRequestResolver;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.OidcRedirectionEndpoint;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.UrlRedaction;
import io.camunda.security.spring.scope.BasePaths;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import io.camunda.security.spring.spi.OidcAuthenticationEntryPoint;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Single source of truth for the CSL webapp filter-chain shape (OIDC oauth2Login and HTTP-Basic
 * form login). The primary {@link OidcWebappSecurityConfiguration} and {@link
 * BasicAuthWebappSecurityConfiguration} delegate here; per-scope webapp chains are built via {@link
 * #buildScopedWebappChain}, which derives its prefixed matchers and endpoints from a {@code
 * basePath}.
 *
 * <p>Shared collaborators (handlers, providers, properties, pathPort) are constructor-injected and
 * held as fields, mirroring {@code ScopedApiSecurityChainBuilder}. Per-invocation inputs (the
 * cluster OAuth2 stack and the {@link HttpSecurity} instance) remain method parameters.
 *
 * <p>The constructor is Spring-wired and is not a stable extension point: it has taken a new
 * collaborator each time the chain gained one (#529, #541, #625), always by extending the single
 * signature rather than by adding an overload. A host obtains this bean from the context — {@link
 * ScopedWebappSecurityChainBuilderConfiguration} is the only place in the library that constructs
 * it — and calls {@link #buildOidcWebappChain} or {@link #buildScopedWebappChain} on it. Those two
 * methods are the surface a host binds to.
 */
public final class ScopedWebappSecurityChainBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(ScopedWebappSecurityChainBuilder.class);

  private final AuthFailureHandler authFailureHandler;
  private final CamundaSecurityLibraryProperties properties;
  private final SecurityPathPort pathPort;
  private final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider;
  private final ObjectProvider<OidcUserService> oidcUserServiceProvider;
  private final ObjectProvider<OAuth2AuthorizationRequestResolver>
      authorizationRequestResolverProvider;
  private final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider;
  private final ObjectProvider<CamundaLoginPickerFilter> oidcLoginPickerProvider;
  private final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider;
  private final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory;
  private final ScopedClientRegistrationFactory scopedClientRegistrationFactory;
  private final CorsConfigurationSource corsSource;
  private final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers;
  private final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider;
  private final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers;
  private final ObjectProvider<OidcProviderConfigurationPort> oidcProviderConfigurationPortProvider;

  public ScopedWebappSecurityChainBuilder(
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<CamundaLoginPickerFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory,
      final CorsConfigurationSource corsSource,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<OidcAuthenticationEntryPoint> oidcAuthenticationEntryPointProvider,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers,
      final ObjectProvider<OidcProviderConfigurationPort> oidcProviderConfigurationPortProvider) {
    this.authFailureHandler = authFailureHandler;
    this.properties = properties;
    this.pathPort = pathPort;
    this.tokenEndpointCustomizerProvider = tokenEndpointCustomizerProvider;
    this.oidcUserServiceProvider = oidcUserServiceProvider;
    this.authorizationRequestResolverProvider = authorizationRequestResolverProvider;
    this.webAppAuthorizationFilterProvider = webAppAuthorizationFilterProvider;
    this.oidcLoginPickerProvider = oidcLoginPickerProvider;
    this.adminUserCheckFilterProvider = adminUserCheckFilterProvider;
    this.authorizedClientManagerFactory = authorizedClientManagerFactory;
    this.scopedClientRegistrationFactory = scopedClientRegistrationFactory;
    this.corsSource = corsSource;
    this.httpsRedirectCustomizers = httpsRedirectCustomizers;
    this.oidcAuthenticationEntryPointProvider = oidcAuthenticationEntryPointProvider;
    this.securityHeadersCustomizers = securityHeadersCustomizers;
    this.oidcProviderConfigurationPortProvider = oidcProviderConfigurationPortProvider;
  }

  /**
   * Builds the OIDC oauth2Login webapp chain for the primary (non-scoped) webapp paths. Matchers
   * are derived from {@link SecurityPathPort#webappPaths()} and {@link
   * SecurityPathPort#unauthenticatedWebappPaths()}; login/logout/redirect URLs use the CSL
   * constants.
   *
   * <p>The supplied {@code sessionRepositoryFilter} is installed before {@link
   * SecurityContextHolderFilter} (see ADR-0009).
   */
  public SecurityFilterChain buildOidcWebappChain(
      final HttpSecurity http,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    Objects.requireNonNull(sessionRepositoryFilter, "sessionRepositoryFilter must not be null");

    final var matchers = withHeartbeatMatcher(pathPort.webappPaths(), HEARTBEAT_URL);
    final var unauthenticatedMatchers = pathPort.unauthenticatedWebappPaths();
    final var loginUrl = LOGIN_URL;
    final var logoutUrl = LOGOUT_URL;
    // The OAuth2 redirection-endpoint path (where Spring listens for the authorization-code
    // callback) is derived from the configured client redirect-uri, so a host can align it with the
    // callback its IdP client already has registered (ADR-0018). Defaults to REDIRECT_URI
    // (/sso-callback) when redirect-uri is unset, preserving existing behaviour. The servlet
    // context-path is stripped so the path stays context-relative: Spring's redirection-endpoint
    // matcher matches the context-path-relative request path, so a redirect-uri that embeds the
    // context-path (as the 8.10 chart renders for a context-path'd webapp) would otherwise never
    // match the callback and loop the login (GH-569).
    final var authentication = properties.getAuthentication();
    final var oidc = authentication != null ? authentication.getOidc() : null;
    // The flat block drives this endpoint whether or not it also contributes a client registration,
    // so validate it here: a value set without a client-id is not part of the provider map and
    // would otherwise fall back to the default callback while the IdP redirects elsewhere.
    // The registration id is only passed when the flat block contributes a registration: a
    // redirect-only block's id names nothing, and the endpoint mounts the placeholder as a
    // wildcard.
    scopedClientRegistrationFactory.validateRedirectionEndpointSource(
        oidc != null ? oidc.getRedirectUri() : null,
        oidc != null && StringUtils.hasText(oidc.getClientId()) ? oidc.getRegistrationId() : null);
    final var redirectUri =
        OidcRedirectionEndpoint.resolve(
            oidc != null ? oidc.getRedirectUri() : null, servletContextPath(http), REDIRECT_URI);

    // Install the session filter before the security context filter.
    http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(unauthenticatedMatchers.toArray(String[]::new))
                        .permitAll()
                        // loginUrl/logoutUrl are normally intercepted by the oauth2Login/logout
                        // filters before the authorization rule runs; permit them defensively so a
                        // host supplying its own loginPage controller (or the multi-IdP fallback to
                        // loginUrl) cannot hit a redirect loop.
                        .requestMatchers(loginUrl, logoutUrl)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            resolveOidcAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, "/oauth2/authorization"))
                        .accessDeniedHandler(authFailureHandler))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            // No oauth2ResourceServer on the webapp chain: it authenticates users interactively via
            // oauth2Login and serves them from the session. Bearer/JWT (client-credentials, direct
            // API access) is the API chain's responsibility (ADR-0011); a bearer token presented to
            // a webapp path falls through to the delegating entry point below, which returns 401.
            .oauth2Login(
                oauthLogin -> {
                  oauthLogin
                      .clientRegistrationRepository(clientRegistrationRepository)
                      // A declared login page keeps OAuth2LoginConfigurer#init out of the branch
                      // that reads the registration repository to build login links of its own.
                      // That branch resolves the discovery document of each issuer while the
                      // context still starts, so one provider the application cannot reach stops
                      // the start. The entry point that exceptionHandling above installs already
                      // sends the same redirect.
                      .loginPage(loginUrl)
                      .authorizedClientRepository(authorizedClientRepository)
                      .redirectionEndpoint(
                          redirectionEndpoint -> redirectionEndpoint.baseUri(redirectUri))
                      .failureHandler(new OAuth2AuthenticationExceptionHandler());
                  tokenEndpointCustomizerProvider.ifAvailable(oauthLogin::tokenEndpoint);
                  oidcUserServiceProvider.ifAvailable(
                      service -> oauthLogin.userInfoEndpoint(c -> c.oidcUserService(service)));
                  authorizationRequestResolverProvider.ifAvailable(
                      resolver ->
                          oauthLogin.authorizationEndpoint(
                              authorization ->
                                  authorization.authorizationRequestResolver(resolver)));
                })
            .oidcLogout(oidcLogout -> {})
            .logout(
                logout -> {
                  logout
                      .logoutUrl(logoutUrl)
                      .deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN)
                      .invalidateHttpSession(true);
                  logout.logoutSuccessHandler(
                      oidcLogoutSuccessHandler(
                          clientRegistrationRepository, "", primaryOidcSources()));
                });

    // Heartbeat is installed first among AuthorizationFilter-anchored filters (insertion order is
    // the tie-break for filters sharing an anchor) so a heartbeat call short-circuits with 204
    // before token refresh or webapp-authorization checks a keep-alive ping has no need to trigger.
    filterChainBuilder.addFilterAfter(new SessionHeartbeatFilter(), AuthorizationFilter.class);

    // Refresh expired access tokens transparently after AuthorizationFilter; the logout handler
    // force-logs-out users whose refresh token has also expired.
    final var logoutHandler =
        new CompositeLogoutHandler(
            new CookieClearingLogoutHandler(SESSION_COOKIE, X_CSRF_TOKEN),
            new SecurityContextLogoutHandler());
    filterChainBuilder.addFilterAfter(
        new OAuth2RefreshTokenFilter(
            authorizedClientRepository, authorizedClientManager, logoutHandler),
        AuthorizationFilter.class);

    // AdminUserCheckFilter is intentionally NOT wired on the OIDC chain (ADR-0004, GH-189): under
    // OIDC, admin provisioning is driven by IdP claims, and the filter cannot tell "no admin yet"
    // from "membership not yet projected". Only WebAppAuthorizationCheck runs here.
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      filterChainBuilder.addFilterAfter(webAppFilter, OAuth2RefreshTokenFilter.class);
    }

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    // Install the multi-IdP login picker (GH-269): the custom entry point trips
    // DefaultLoginPageConfigurer's gate, so the picker would otherwise be dropped and multi-IdP
    // deployments 302 to /login -> 404. Must be added after applyCsrfConfiguration — both anchor on
    // CsrfFilter and the stable sort makes insertion order the tie-break, so the CSRF header filter
    // writes before the picker commits the response.
    final var loginPickerFilter =
        oidcLoginPickerProvider.getIfAvailable(
            () -> new CamundaLoginPickerFilter(clientRegistrationRepository, loginUrl));
    filterChainBuilder.addFilterAfter(loginPickerFilter, CsrfFilter.class);

    applyOidcRedirectDiagnosticsFilter(filterChainBuilder, redirectUri);

    return filterChainBuilder.build();
  }

  /**
   * Appends {@code heartbeatPath} to the chain's securityMatcher patterns so the heartbeat endpoint
   * is always reachable, independent of whatever the host declared in {@code
   * SecurityPathPort#webappPaths()} (ADR-0020) — unlike {@code LOGIN_URL}/{@code LOGOUT_URL}, which
   * rely on the host's own declared patterns already covering them.
   */
  // package-private for unit testing
  static List<String> withHeartbeatMatcher(
      final Iterable<String> basePaths, final String heartbeatPath) {
    final var combined = new ArrayList<String>();
    basePaths.forEach(combined::add);
    combined.add(heartbeatPath);
    return combined;
  }

  /**
   * Builds the HTTP-Basic form-login webapp chain for the primary (non-scoped) webapp paths.
   * Matchers, login URL, and logout URL are derived from the injected {@link SecurityPathPort} and
   * CSL constants.
   *
   * <p>The supplied {@code sessionRepositoryFilter} is installed before {@link
   * SecurityContextHolderFilter} (see ADR-0009).
   */
  public SecurityFilterChain buildBasicWebappChain(
      final HttpSecurity http, final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    Objects.requireNonNull(sessionRepositoryFilter, "sessionRepositoryFilter must not be null");

    final var heartbeatUrl = HEARTBEAT_URL;
    final var matchers = withHeartbeatMatcher(pathPort.webappPaths(), heartbeatUrl);
    final var loginUrl = LOGIN_URL;
    final var logoutUrl = LOGOUT_URL;

    // Install the session filter before the security context filter.
    http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    // Unlike every other path on this chain, the heartbeat endpoint must not be
                    // reachable without authentication — permitAll below is otherwise the norm for
                    // Basic-auth webapp chains (business paths are gated downstream by
                    // AdminUserCheckFilter/WebAppAuthorizationCheckFilter instead), but this
                    // endpoint has no such downstream gate of its own.
                    auth.requestMatchers(heartbeatUrl).authenticated().anyRequest().permitAll())
            .anonymous(AbstractHttpConfigurer::disable)
            .formLogin(
                formLogin ->
                    formLogin
                        .loginPage(loginUrl)
                        .loginProcessingUrl(loginUrl)
                        .failureHandler(authFailureHandler)
                        .successHandler(
                            (request, response, authentication) -> {
                              response.setStatus(HttpStatus.NO_CONTENT.value());
                              final CsrfToken token =
                                  (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                              if (token != null) {
                                response.setHeader(X_CSRF_TOKEN, token.getToken());
                              }
                            }))
            .logout(
                logout ->
                    logout
                        .logoutUrl(logoutUrl)
                        .logoutSuccessHandler(
                            (request, response, authentication) ->
                                response.setStatus(HttpStatus.NO_CONTENT.value()))
                        .deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN))
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler));

    // Installed first among AuthorizationFilter-anchored filters (see buildOidcWebappChain) so a
    // heartbeat call short-circuits with 204 before the admin-presence/webapp-authorization checks.
    filterChainBuilder.addFilterAfter(new SessionHeartbeatFilter(), AuthorizationFilter.class);

    final var adminFilter = adminUserCheckFilterProvider.getIfAvailable();
    if (adminFilter != null) {
      filterChainBuilder.addFilterAfter(adminFilter, AuthorizationFilter.class);
    }
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      final var anchor =
          adminFilter != null ? AdminUserCheckFilter.class : AuthorizationFilter.class;
      filterChainBuilder.addFilterAfter(webAppFilter, anchor);
    }

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  /**
   * Builds the per-scope webapp chain for the given {@code basePath} and {@code authentication}
   * configuration. Derives prefixed matchers and endpoint URLs from the basePath and delegates to
   * either the OIDC or BASIC chain builder depending on the authentication method.
   *
   * <p>For OIDC scopes, builds a per-scope OAuth2 client stack: a {@link
   * LazyClientRegistrationRepository} over the descriptor's providers, an {@link
   * HttpSessionOAuth2AuthorizedClientRepository}, an {@link OAuth2AuthorizedClientManager} via the
   * injected factory, and a prefix-aware {@link CamundaOidcAuthorizationRequestResolver}. The login
   * picker is also prefix-aware so its authorization links point to {@code
   * <basePath>/oauth2/authorization/<id>}.
   *
   * <p>The supplied {@code sessionRepositoryFilter} is installed before {@link
   * SecurityContextHolderFilter} so the Spring-Session-backed, Path-scoped session is available
   * throughout the filter chain.
   */
  public SecurityFilterChain buildScopedWebappChain(
      final HttpSecurity http,
      final String basePath,
      final AuthenticationConfiguration authentication,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String scopedSessionCookieName,
      final String scopedCsrfCookieName)
      throws Exception {
    Objects.requireNonNull(http, "http must not be null");
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(authentication, "authentication must not be null");
    Objects.requireNonNull(pathPort, "pathPort must not be null");
    Objects.requireNonNull(properties, "properties must not be null");
    Objects.requireNonNull(authentication.getMethod(), "authentication.method must not be null");
    Objects.requireNonNull(sessionRepositoryFilter, "sessionRepositoryFilter must not be null");
    Objects.requireNonNull(scopedSessionCookieName, "scopedSessionCookieName must not be null");
    Objects.requireNonNull(scopedCsrfCookieName, "scopedCsrfCookieName must not be null");
    Objects.requireNonNull(
        authorizedClientManagerFactory, "authorizedClientManagerFactory must not be null");
    Objects.requireNonNull(
        scopedClientRegistrationFactory, "scopedClientRegistrationFactory must not be null");

    final var prefix = BasePaths.normalize(basePath, "basePath");
    if (prefix.isEmpty()) {
      throw new IllegalArgumentException(
          "basePath must not be the root path '/' for a scoped chain, but was: " + basePath);
    }
    if (pathPort.webappPaths() == null || pathPort.webappPaths().isEmpty()) {
      // Host provides no webapp paths — return a no-op chain that matches nothing.
      return http.securityMatcher(request -> false)
          .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
          .build();
    }
    return switch (authentication.getMethod()) {
      case OIDC ->
          buildOidcWebappChainInternal(
              http,
              prefix,
              authentication,
              sessionRepositoryFilter,
              scopedSessionCookieName,
              scopedCsrfCookieName);
      case BASIC ->
          buildBasicWebappChainInternal(
              http, prefix, sessionRepositoryFilter, scopedSessionCookieName, scopedCsrfCookieName);
      default ->
          throw new IllegalStateException(
              "Unsupported authentication method: " + authentication.getMethod());
    };
  }

  /**
   * Reads {@code server.servlet.context-path} from the application {@link
   * org.springframework.core.env.Environment} reachable through {@link HttpSecurity}'s shared
   * {@link ApplicationContext}. Returns {@code ""} when unset or when no context is available, so
   * the caller strips nothing.
   */
  private static String servletContextPath(final HttpSecurity http) {
    final var context = http.getSharedObject(ApplicationContext.class);
    return context != null
        ? context.getEnvironment().getProperty("server.servlet.context-path", "")
        : "";
  }

  /**
   * Builds the {@code post_logout_redirect_uri} template {@code "{baseUrl}" + prefix + route}. The
   * literal {@code prefix} (the chain's normalized base path, {@code ""} for the primary chain)
   * adds back the CSL base path that {@code {baseUrl}} drops. Returns {@code ""} when no route is
   * configured, or when the configured route is blank/whitespace (treated as absent), so callers
   * send no {@code post_logout_redirect_uri}.
   *
   * @throws IllegalArgumentException if a non-blank route does not start with {@code "/"}.
   */
  static String postLogoutRedirectUri(final String prefix, final Optional<String> route) {
    final String path = route.orElse("");
    if (path.isBlank()) {
      return "";
    }
    if (!path.startsWith("/")) {
      throw new IllegalArgumentException(
          "postLogoutRedirectPath must start with '/', but was: " + path);
    }
    return "{baseUrl}" + prefix + path;
  }

  /**
   * The cluster's authentication configuration, never null.
   *
   * <p>{@link CamundaSecurityLibraryProperties#setAuthentication} does not null-guard, and the
   * class treats an absent authentication section as valid elsewhere (see its {@code
   * isApiProtected()} and {@code validate()}), so the primary chain must not dereference it
   * blindly. Scoped chains need no equivalent: their {@code AuthenticationConfiguration} is
   * null-checked on entry.
   */
  private AuthenticationConfiguration clusterAuthentication() {
    final var authentication = properties.getAuthentication();
    return authentication == null ? new AuthenticationConfiguration() : authentication;
  }

  /**
   * The {@code post_logout_redirect_uri} template to send for each OIDC registration in the scope,
   * where {@code ""} means "send none for this registration".
   *
   * <p>Built from {@link ScopedClientRegistrationFactory#flatten} — the same registrationId-keyed
   * map the chain's {@link ClientRegistrationRepository} is built from, covering the flat {@code
   * oidc.*} block and every {@code providers.oidc.<id>} entry — so a deployment with several IdPs
   * gets each one's own answer. Reading {@code authentication.getOidc()} alone would silently
   * ignore any provider declared only under {@code providers.oidc.*}.
   *
   * <p>The map is total over the scope's registrations, so the handler never has to fall back to a
   * chain-wide default: whatever it finds for a registrationId is that registration's final answer.
   *
   * <p>ADR-0026. This replaced a single per-scope boolean, which forced one strict IdP to strip the
   * redirect from every other IdP in the scope (ADR-0023).
   */
  private Map<String, String> postLogoutRedirectUris(
      final Map<String, OidcConfiguration> sources, final String prefix) {
    return postLogoutRedirectUris(
        scopedClientRegistrationFactory, sources, prefix, composedPostLogoutRedirectUri(prefix));
  }

  // Package-private for unit testing, like postLogoutRedirectUri(String, Optional) above: takes
  // the factory and the composed default explicitly so a test can exercise the wiring between
  // isPostLogoutRedirectUriUsable and postLogoutRedirectUri without constructing a full builder.
  static Map<String, String> postLogoutRedirectUris(
      final ScopedClientRegistrationFactory clientRegistrationFactory,
      final Map<String, OidcConfiguration> sources,
      final String prefix,
      final String composedDefault) {
    // The factory validates these when it builds the registrations, which is the usual path. A host
    // that replaces the ClientRegistrationRepository bean bypasses that, and this handler is still
    // configured from the provider map — so the map actually consumed is validated here too. The
    // rules live in one place; this only calls them.
    clientRegistrationFactory.validatePostLogoutRedirectUris(sources);
    final Map<String, String> redirectUris = new LinkedHashMap<>();
    sources.forEach(
        (registrationId, oidc) -> {
          // A blank/null registrationId already gets its own warning above, and can never be the
          // authenticated registration id a real logout looks this map up by — Map.copyOf below
          // rejects a null key, so keeping such an entry would still crash chain construction.
          if (!StringUtils.hasText(registrationId)) {
            return;
          }
          redirectUris.put(
              registrationId,
              postLogoutRedirectUri(
                  registrationId,
                  oidc,
                  prefix,
                  composedDefault,
                  clientRegistrationFactory.isPostLogoutRedirectUriUsable(registrationId, oidc)));
        });
    return redirectUris;
  }

  /**
   * The provider configurations backing the primary chain, taken from the same source its {@link
   * ClientRegistrationRepository} is built from.
   *
   * <p>{@code OidcWebappClientBeansConfiguration#clientRegistrationRepository} builds the primary
   * repository from {@link OidcProviderConfigurationPort}, and both that bean and the port's
   * default implementation are {@code @ConditionalOnMissingBean} — {@code
   * OidcAuthenticationConfigurationRepository#initializeProviders} is even {@code protected} for
   * the purpose. A host that overrides either supplies its own registrationIds <em>and</em> its own
   * {@link OidcConfiguration} instances, post-logout settings included. Flattening the library
   * properties instead would silently ignore those settings, or worse, key a configured value to a
   * registrationId the repository never issues.
   *
   * <p>Falls back to the cluster properties when no port is present, which is what the port's own
   * default implementation resolves to anyway.
   *
   * <p>The registrationId is the join key, and that is the whole contract. A host may replace only
   * the {@link ClientRegistrationRepository} bean and leave the port at its default, in which case
   * a registration whose id also appears in the port's map takes that entry's post-logout settings
   * — the operator keyed configuration to that id, so honouring it is the point. An id that means
   * two different providers in the two sources is contradictory configuration rather than something
   * CSL can detect: a repository need not be {@code Iterable} (see {@code LoginLinksBuilder}), so
   * the two sets cannot be compared in general, and matching ids would not prove common provenance
   * anyway. An id absent from the map keeps the chain-wide default.
   */
  private Map<String, OidcConfiguration> primaryOidcSources() {
    final var port = oidcProviderConfigurationPortProvider.getIfAvailable();
    return port != null
        ? port.getOidcAuthenticationConfigurations()
        : scopedClientRegistrationFactory.flatten(clusterAuthentication());
  }

  /**
   * One provider's {@code post_logout_redirect_uri} template, or {@code ""} to send none.
   *
   * <p>Composition only. The value's shape is checked separately, by {@link
   * ScopedClientRegistrationFactory}, which validates every OIDC provider block in one place
   * (ADR-0026) — but only warns about one it considers unusable, rather than stopping the
   * application (see that class's own Javadoc). {@code usable} carries that verdict here, so a
   * value the factory warned about falls back to {@code composedDefault} instead of reaching {@code
   * buildAndExpand} at logout, where it would only fail then.
   *
   * <p>A value starting with {@code /} is a path and resolves against this chain just as the host's
   * own route does, keeping per-scope resolution. Anything else is a URI template handed to Spring
   * untouched, and deliberately does <em>not</em> pick up the chain's base path: a deployment
   * served under a per-cluster prefix needs a URL its IdP can have registered, and the prefix is
   * exactly what makes the composed one unregisterable at an OP like Auth0.
   *
   * <p>{@code post-logout-redirect-enabled=false} wins over a configured URI. An operator with both
   * set is saying "this IdP rejects the parameter", which is the more specific statement; sending
   * the URI anyway would resurrect the very rejection the flag exists to avoid. It is logged,
   * because silently ignoring an explicitly configured value is otherwise an afternoon lost.
   */
  // Package-private for unit testing, like postLogoutRedirectUri(String, Optional) above.
  static String postLogoutRedirectUri(
      final String registrationId,
      final OidcConfiguration oidc,
      final String prefix,
      final String composedDefault,
      final boolean usable) {
    final var configured = oidc.getPostLogoutRedirectUri();
    final var value = StringUtils.hasText(configured) ? configured.trim() : null;
    if (!oidc.isPostLogoutRedirectEnabled()) {
      if (value != null) {
        // The registrationId locates the offending configuration on its own, so the value itself
        // adds nothing here and is left out rather than redacted.
        LOG.warn(
            "OIDC registration '{}' sets both post-logout-redirect-uri and "
                + "post-logout-redirect-enabled=false; the configured URI is ignored and no "
                + "post_logout_redirect_uri will be sent. Remove one of the two to make the intent "
                + "unambiguous.",
            ScopedClientRegistrationFactory.sanitizeForLog(registrationId));
      }
      return "";
    }
    if (value == null || !usable) {
      return composedDefault;
    }
    return value.startsWith("/") ? "{baseUrl}" + prefix + value : value;
  }

  /** The host-declared route, composed against the chain, used when nothing is configured. */
  private String composedPostLogoutRedirectUri(final String prefix) {
    final var route =
        Objects.requireNonNull(
            pathPort.postLogoutRedirectPath(),
            "SecurityPathPort#postLogoutRedirectPath() must not return null; "
                + "return Optional.empty() to send no post_logout_redirect_uri");
    return postLogoutRedirectUri(prefix, route);
  }

  /**
   * Builds the chain's logout success handler, resolving {@code post_logout_redirect_uri} per
   * registration.
   *
   * <p>{@code authentication} is the scope the chain belongs to — the cluster's for the primary
   * chain, the tenant's for a scoped one — so a scoped chain pointing at its own IdP(s) reads their
   * post-logout configuration, matching how its registrations and end-session endpoints are already
   * resolved per scope.
   */
  private LogoutSuccessHandler oidcLogoutSuccessHandler(
      final ClientRegistrationRepository repo,
      final String prefix,
      final Map<String, OidcConfiguration> sources) {
    final var redirectUris = postLogoutRedirectUris(sources, prefix);
    final var handler = new CamundaOidcLogoutSuccessHandler(repo, redirectUris);
    // The chain-wide default still has to be set, for registrations the map does not cover. A host
    // may supply its own ClientRegistrationRepository — CSL's default bean is
    // @ConditionalOnMissingBean
    // — holding registrations that never appear under camunda.security.authentication.*. Those are
    // absent from the map, and before ADR-0026 they got this composed route like everyone else;
    // leaving it unset would silently drop their post_logout_redirect_uri.
    final var composedDefault = composedPostLogoutRedirectUri(prefix);
    if (!composedDefault.isEmpty()) {
      handler.setPostLogoutRedirectUri(composedDefault);
    }
    if (LOG.isDebugEnabled()) {
      redirectUris.forEach(
          (registrationId, uri) -> {
            final var safeId = ScopedClientRegistrationFactory.sanitizeForLog(registrationId);
            if (uri.isEmpty()) {
              LOG.debug(
                  "post_logout_redirect_uri is disabled for OIDC registration '{}'; "
                      + "the IdP will apply its own post-logout default.",
                  safeId);
            } else {
              LOG.debug(
                  "OIDC registration '{}' will send post_logout_redirect_uri '{}'.",
                  safeId,
                  UrlRedaction.redact(uri));
            }
          });
    }
    return handler;
  }

  // Moved verbatim from OidcWebappSecurityConfiguration; package-private for unit testing.
  static AuthenticationEntryPoint oidcWebappAuthenticationEntryPoint(
      final ClientRegistrationRepository clientRegistrationRepository, final String loginUrl) {
    return oidcWebappAuthenticationEntryPoint(
        clientRegistrationRepository, loginUrl, "/oauth2/authorization");
  }

  // Package-private for unit testing; authorizationBaseUri allows per-scope prefix.
  static AuthenticationEntryPoint oidcWebappAuthenticationEntryPoint(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginUrl,
      final String authorizationBaseUri) {
    final var bearerEntryPoint = new BearerTokenAuthenticationEntryPoint();
    final var oauthRedirectEntryPoint =
        new LoginUrlAuthenticationEntryPoint(
            resolveOauthRedirectTarget(
                clientRegistrationRepository, loginUrl, authorizationBaseUri));
    // The LinkedHashMap constructor and setDefaultEntryPoint(...) are both @Deprecated in favor of
    // this constructor, which takes the default entry point and matcher entries together.
    return new DelegatingAuthenticationEntryPoint(
        oauthRedirectEntryPoint,
        new RequestMatcherEntry<>(
            new RequestHeaderRequestMatcher("Authorization"), bearerEntryPoint));
  }

  /**
   * Prefers any {@link OidcAuthenticationEntryPoint} bean present in the application context over
   * the library default, following the same "adopter hook with a built-in fallback" pattern as
   * {@link HttpsRedirectCustomizer}. {@code ObjectProvider.getIfAvailable(Supplier)} isn't used
   * here: its fallback factory would have to return {@link OidcAuthenticationEntryPoint}, not the
   * broader {@link AuthenticationEntryPoint} the static default actually produces, so it would need
   * wrapping in a throwaway lambda purely to satisfy that type. The plain {@code getIfAvailable()}
   * plus null-check below avoids that indirection and matches the idiom this class already uses for
   * {@code webAppAuthorizationFilterProvider} and {@code adminUserCheckFilterProvider}.
   *
   * <p><b>Note:</b> this adopts <em>any</em> {@link OidcAuthenticationEntryPoint} bean in context —
   * a host-registered override or {@link OidcAuthenticationEntryPointConfiguration}'s own
   * library-supplied default are indistinguishable here. That default is a plain redirect with no
   * bearer-vs-browser distinction; co-importing {@link OidcAuthenticationEntryPointConfiguration}
   * alongside this builder replaces the bearer-aware {@code DelegatingAuthenticationEntryPoint}
   * fallback below and changes bearer-token requests from 401 to a redirect. This is a known,
   * intentional consequence of adopting the SPI wholesale — see {@code
   * scopedChainAdoptsLibraryDefaultOidcEntryPointWhenBothConfigurationsArePresent} for the
   * characterization test pinning this behavior so a future change to precedence is made
   * deliberately, not accidentally.
   */
  private AuthenticationEntryPoint resolveOidcAuthenticationEntryPoint(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginUrl,
      final String authorizationBaseUri) {
    final var configuredEntryPoint = oidcAuthenticationEntryPointProvider.getIfAvailable();
    if (configuredEntryPoint != null) {
      LOG.debug(
          "Using configured OidcAuthenticationEntryPoint bean ({}) for OIDC webapp chain"
              + " (loginUrl={})",
          configuredEntryPoint.getClass().getName(),
          loginUrl);
      return configuredEntryPoint;
    }
    LOG.debug(
        "No OidcAuthenticationEntryPoint bean registered; using the built-in default for OIDC"
            + " webapp chain (loginUrl={})",
        loginUrl);
    return oidcWebappAuthenticationEntryPoint(
        clientRegistrationRepository, loginUrl, authorizationBaseUri);
  }

  // Moved verbatim from OidcWebappSecurityConfiguration; package-private for unit testing.
  static String resolveOauthRedirectTarget(
      final ClientRegistrationRepository clientRegistrationRepository, final String loginUrl) {
    return resolveOauthRedirectTarget(
        clientRegistrationRepository, loginUrl, "/oauth2/authorization");
  }

  // Package-private for unit testing; authorizationBaseUri allows per-scope prefix.
  static String resolveOauthRedirectTarget(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginUrl,
      final String authorizationBaseUri) {
    final var defaultTarget = authorizationBaseUri + "/" + OIDC_REGISTRATION_ID;
    // A lazy repository answers from the configuration. This code runs while the application
    // builds the chain, and iteration resolves each registration against its identity provider.
    if (clientRegistrationRepository instanceof final LazyClientRegistrationRepository lazy) {
      final var registrationIds = lazy.registrationIds();
      if (registrationIds.isEmpty()) {
        return defaultTarget;
      }
      if (registrationIds.size() > 1) {
        return loginUrl;
      }
      return authorizationBaseUri + "/" + registrationIds.iterator().next();
    }
    if (!(clientRegistrationRepository instanceof final Iterable<?> iterable)) {
      return defaultTarget;
    }
    final var iterator = iterable.iterator();
    if (!iterator.hasNext()) {
      return defaultTarget;
    }
    final Object first = iterator.next();
    if (iterator.hasNext()) {
      return loginUrl;
    }
    if (first instanceof final ClientRegistration registration) {
      return authorizationBaseUri + "/" + registration.getRegistrationId();
    }
    return defaultTarget;
  }

  private SecurityFilterChain buildOidcWebappChainInternal(
      final HttpSecurity http,
      final String prefix,
      final AuthenticationConfiguration authentication,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String scopedSessionCookieName,
      final String scopedCsrfCookieName)
      throws Exception {

    final var matchers =
        withHeartbeatMatcher(
            pathPort.webappPaths().stream().map(p -> prefix + p).toList(), prefix + HEARTBEAT_URL);
    final var unauthenticatedMatchers =
        pathPort.unauthenticatedWebappPaths().stream().map(p -> prefix + p).toList();
    final var loginUrl = prefix + CamundaSecurityFilterChainConstants.LOGIN_URL;
    final var logoutUrl = prefix + CamundaSecurityFilterChainConstants.LOGOUT_URL;
    final var redirectUri = prefix + CamundaSecurityFilterChainConstants.REDIRECT_URI;
    final var authorizationBaseUri = prefix + "/oauth2/authorization";
    final var providerMap = scopedClientRegistrationFactory.flatten(authentication);
    if (providerMap.isEmpty()) {
      throw new IllegalStateException(
          "OIDC scope '"
              + prefix
              + "' has no configured providers; "
              + "a scoped OIDC webapp chain requires at least one provider");
    }
    final var clientRegistrationRepository =
        new LazyClientRegistrationRepository(
            scopedClientRegistrationFactory, providerMap, redirectUri, "basePath=" + prefix);
    final var authorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();
    final var authorizedClientManager =
        authorizedClientManagerFactory.create(
            clientRegistrationRepository, authorizedClientRepository);
    final var scopedResolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, providerMap, authorizationBaseUri);
    final var scopedPicker =
        new CamundaLoginPickerFilter(clientRegistrationRepository, loginUrl, prefix);

    // Install the per-scope session filter before the security context filter so the Spring-Session
    // backed, Path-scoped session is available throughout the chain.
    http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(unauthenticatedMatchers.toArray(String[]::new))
                        .permitAll()
                        // loginUrl/logoutUrl are normally intercepted by the oauth2Login/logout
                        // filters before the authorization rule runs; permit them defensively so a
                        // host supplying its own loginPage controller (or the multi-IdP fallback to
                        // loginUrl) cannot hit a redirect loop.
                        .requestMatchers(loginUrl, logoutUrl)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            resolveOidcAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, authorizationBaseUri))
                        .accessDeniedHandler(authFailureHandler))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            // No oauth2ResourceServer on the webapp chain: it authenticates users interactively via
            // oauth2Login and serves them from the session. Bearer/JWT (client-credentials, direct
            // API access) is the API chain's responsibility (ADR-0011); a bearer token presented to
            // a webapp path falls through to the delegating entry point below, which returns 401.
            .oauth2Login(
                oauthLogin -> {
                  oauthLogin
                      .clientRegistrationRepository(clientRegistrationRepository)
                      // A declared login page keeps OAuth2LoginConfigurer#init out of the branch
                      // that reads the registration repository to build login links of its own.
                      // That branch resolves the discovery document of each issuer while the
                      // context still starts, so one provider the application cannot reach stops
                      // the start. The entry point that exceptionHandling above installs already
                      // sends the same redirect.
                      .loginPage(loginUrl)
                      .authorizedClientRepository(authorizedClientRepository)
                      .redirectionEndpoint(
                          redirectionEndpoint -> redirectionEndpoint.baseUri(redirectUri))
                      .failureHandler(new OAuth2AuthenticationExceptionHandler());
                  tokenEndpointCustomizerProvider.ifAvailable(oauthLogin::tokenEndpoint);
                  oidcUserServiceProvider.ifAvailable(
                      service -> oauthLogin.userInfoEndpoint(c -> c.oidcUserService(service)));
                  oauthLogin.authorizationEndpoint(
                      authorization -> authorization.authorizationRequestResolver(scopedResolver));
                })
            .oidcLogout(oidcLogout -> {})
            .logout(
                logout -> {
                  logout
                      .logoutUrl(logoutUrl)
                      .invalidateHttpSession(true)
                      .addLogoutHandler(
                          pathScopedCookieClearingLogoutHandler(scopedSessionCookieName, prefix))
                      .addLogoutHandler(
                          pathScopedCookieClearingLogoutHandler(scopedCsrfCookieName, prefix));
                  logout.logoutSuccessHandler(
                      oidcLogoutSuccessHandler(
                          clientRegistrationRepository,
                          prefix,
                          scopedClientRegistrationFactory.flatten(authentication)));
                });

    // Installed first among AuthorizationFilter-anchored filters (see buildOidcWebappChain) so a
    // heartbeat call short-circuits with 204 before token refresh or webapp-authorization checks.
    filterChainBuilder.addFilterAfter(new SessionHeartbeatFilter(), AuthorizationFilter.class);

    // Refresh expired access tokens transparently after AuthorizationFilter; the logout handler
    // force-logs-out users whose refresh token has also expired.
    final var logoutHandler =
        new CompositeLogoutHandler(
            pathScopedCookieClearingLogoutHandler(scopedSessionCookieName, prefix),
            pathScopedCookieClearingLogoutHandler(scopedCsrfCookieName, prefix),
            new SecurityContextLogoutHandler());
    filterChainBuilder.addFilterAfter(
        new OAuth2RefreshTokenFilter(
            authorizedClientRepository, authorizedClientManager, logoutHandler),
        AuthorizationFilter.class);

    // AdminUserCheckFilter is intentionally NOT wired on the OIDC chain (ADR-0004, GH-189): under
    // OIDC, admin provisioning is driven by IdP claims, and the filter cannot tell "no admin yet"
    // from "membership not yet projected". Only WebAppAuthorizationCheck runs here.
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      filterChainBuilder.addFilterAfter(webAppFilter, OAuth2RefreshTokenFilter.class);
    }

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, prefix, scopedCsrfCookieName);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    // Install the multi-IdP login picker (GH-269): the custom entry point trips
    // DefaultLoginPageConfigurer's gate, so the picker would otherwise be dropped and multi-IdP
    // deployments 302 to /login -> 404. Must be added after applyCsrfConfiguration — both anchor on
    // CsrfFilter and the stable sort makes insertion order the tie-break, so the CSRF header filter
    // writes before the picker commits the response.
    filterChainBuilder.addFilterAfter(scopedPicker, CsrfFilter.class);

    applyOidcRedirectDiagnosticsFilter(filterChainBuilder, redirectUri);

    return filterChainBuilder.build();
  }

  private void applyOidcRedirectDiagnosticsFilter(
      final HttpSecurity http, final String callbackPath) {
    final var authentication = properties.getAuthentication();
    final var oidc = authentication != null ? authentication.getOidc() : null;
    if (oidc != null && oidc.getDiagnostics() != null && oidc.getDiagnostics().isEnabled()) {
      // Positioned before the redirect filter so diagnostics wrap the redirect generation and
      // can inspect the resulting Location header on the way back out.
      //
      // Note on scoped chains: callbackPath for a scoped chain is already prefix + REDIRECT_URI
      // (e.g. /operate/sso-callback). OidcRedirectDiagnosticsFilter computes expectedRedirectUri
      // as computeExternalBaseUrl(request) + callbackPath. computeExternalBaseUrl appends
      // X-Forwarded-Prefix (or the servlet context path) to the scheme/host/port. When a reverse
      // proxy sets X-Forwarded-Prefix to the same scope prefix (e.g. /operate), that prefix is
      // counted twice and the redirect_uri mismatch WARN may fire as a false positive. This is a
      // diagnostic limitation only — the actual auth flow is unaffected. Operators seeing a
      // persistent mismatch WARN on a scoped deployment should check whether X-Forwarded-Prefix
      // duplicates the path prefix already present in callbackPath before investigating further.
      http.addFilterBefore(
          new OidcRedirectDiagnosticsFilter(callbackPath),
          OAuth2AuthorizationRequestRedirectFilter.class);
      LOG.info(
          "OIDC redirect diagnostics filter enabled"
              + " (camunda.security.authentication.oidc.diagnostics.enabled=true)."
              + " Enable DEBUG logging for {} to see full redirect diagnostics.",
          OidcRedirectDiagnosticsFilter.class.getName());
    }
  }

  private SecurityFilterChain buildBasicWebappChainInternal(
      final HttpSecurity http,
      final String prefix,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String scopedSessionCookieName,
      final String scopedCsrfCookieName)
      throws Exception {

    final var heartbeatUrl = prefix + HEARTBEAT_URL;
    final var matchers =
        withHeartbeatMatcher(
            pathPort.webappPaths().stream().map(p -> prefix + p).toList(), heartbeatUrl);
    final var loginUrl = prefix + CamundaSecurityFilterChainConstants.LOGIN_URL;
    final var logoutUrl = prefix + CamundaSecurityFilterChainConstants.LOGOUT_URL;

    // Install the per-scope session filter before the security context filter.
    http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                // See buildBasicWebappChain: the heartbeat endpoint, unlike every other path on
                // this chain, must require authentication rather than falling through to permitAll.
                auth -> auth.requestMatchers(heartbeatUrl).authenticated().anyRequest().permitAll())
            .anonymous(AbstractHttpConfigurer::disable)
            .formLogin(
                formLogin ->
                    formLogin
                        .loginPage(loginUrl)
                        .loginProcessingUrl(loginUrl)
                        .failureHandler(authFailureHandler)
                        .successHandler(
                            (request, response, authentication) -> {
                              response.setStatus(HttpStatus.NO_CONTENT.value());
                              final CsrfToken token =
                                  (CsrfToken) request.getAttribute(CsrfToken.class.getName());
                              if (token != null) {
                                response.setHeader(X_CSRF_TOKEN, token.getToken());
                              }
                            }))
            .logout(
                logout ->
                    logout
                        .logoutUrl(logoutUrl)
                        .logoutSuccessHandler(
                            (request, response, authentication) ->
                                response.setStatus(HttpStatus.NO_CONTENT.value()))
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(scopedSessionCookieName, prefix))
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(scopedCsrfCookieName, prefix)))
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler));

    // Installed first among AuthorizationFilter-anchored filters (see buildOidcWebappChain) so a
    // heartbeat call short-circuits with 204 before the admin-presence/webapp-authorization checks.
    filterChainBuilder.addFilterAfter(new SessionHeartbeatFilter(), AuthorizationFilter.class);

    final var adminFilter = adminUserCheckFilterProvider.getIfAvailable();
    if (adminFilter != null) {
      filterChainBuilder.addFilterAfter(adminFilter, AuthorizationFilter.class);
    }
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      final var anchor =
          adminFilter != null ? AdminUserCheckFilter.class : AuthorizationFilter.class;
      filterChainBuilder.addFilterAfter(webAppFilter, anchor);
    }

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, prefix, scopedCsrfCookieName);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  private static LogoutHandler pathScopedCookieClearingLogoutHandler(
      final String cookieName, final String cookiePath) {
    return (request, response, authentication) -> {
      final var cookie = new jakarta.servlet.http.Cookie(cookieName, "");
      cookie.setMaxAge(0);
      // Prepend the context path so the clear path matches the set path under any deployment.
      // request.getContextPath() is a deployment constant — same value for every request.
      cookie.setPath(request.getContextPath() + cookiePath);
      response.addCookie(cookie);
    };
  }
}
