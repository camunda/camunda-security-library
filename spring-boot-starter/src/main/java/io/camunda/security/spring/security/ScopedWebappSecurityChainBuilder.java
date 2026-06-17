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
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.OIDC_REGISTRATION_ID;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.AdminUserCheckFilter;
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler;
import io.camunda.security.spring.oidc.CamundaOidcAuthorizationRequestResolver;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.scope.BasePaths;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import java.util.LinkedHashMap;
import java.util.Objects;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
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
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.session.web.http.SessionRepositoryFilter;

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
 */
public final class ScopedWebappSecurityChainBuilder {

  private final AuthFailureHandler authFailureHandler;
  private final CamundaSecurityLibraryProperties properties;
  private final SecurityPathPort pathPort;
  private final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider;
  private final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider;
  private final ObjectProvider<OidcUserService> oidcUserServiceProvider;
  private final ObjectProvider<OAuth2AuthorizationRequestResolver>
      authorizationRequestResolverProvider;
  private final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider;
  private final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider;
  private final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider;
  private final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory;
  private final ScopedClientRegistrationFactory scopedClientRegistrationFactory;

  public ScopedWebappSecurityChainBuilder(
      final AuthFailureHandler authFailureHandler,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ScopedClientRegistrationFactory scopedClientRegistrationFactory) {
    this.authFailureHandler = authFailureHandler;
    this.properties = properties;
    this.pathPort = pathPort;
    this.tokenEndpointCustomizerProvider = tokenEndpointCustomizerProvider;
    this.logoutSuccessHandlerProvider = logoutSuccessHandlerProvider;
    this.oidcUserServiceProvider = oidcUserServiceProvider;
    this.authorizationRequestResolverProvider = authorizationRequestResolverProvider;
    this.webAppAuthorizationFilterProvider = webAppAuthorizationFilterProvider;
    this.oidcLoginPickerProvider = oidcLoginPickerProvider;
    this.adminUserCheckFilterProvider = adminUserCheckFilterProvider;
    this.authorizedClientManagerFactory = authorizedClientManagerFactory;
    this.scopedClientRegistrationFactory = scopedClientRegistrationFactory;
  }

  /**
   * Builds the OIDC oauth2Login webapp chain for the primary (non-scoped) webapp paths. Matchers
   * are derived from {@link SecurityPathPort#webappPaths()} and {@link
   * SecurityPathPort#unauthenticatedWebappPaths()}; login/logout/redirect URLs use the CSL
   * constants.
   */
  public SecurityFilterChain buildOidcWebappChain(
      final HttpSecurity http,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager)
      throws Exception {

    final var matchers = pathPort.webappPaths();
    final var unauthenticatedMatchers = pathPort.unauthenticatedWebappPaths();
    final var loginUrl = LOGIN_URL;
    final var logoutUrl = LOGOUT_URL;
    final var redirectUri = REDIRECT_URI;

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
                            oidcWebappAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl))
                        .accessDeniedHandler(authFailureHandler))
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            // No oauth2ResourceServer on the webapp chain: it authenticates users interactively via
            // oauth2Login and serves them from the session. Bearer/JWT (client-credentials, direct
            // API access) is the API chain's responsibility (ADR-0023); a bearer token presented to
            // a webapp path falls through to the delegating entry point below, which returns 401.
            .oauth2Login(
                oauthLogin -> {
                  oauthLogin
                      .clientRegistrationRepository(clientRegistrationRepository)
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
                  logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
                });

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

    // AdminUserCheckFilter is intentionally NOT wired on the OIDC chain (ADR-0011, GH-189): under
    // OIDC, admin provisioning is driven by IdP claims, and the filter cannot tell "no admin yet"
    // from "membership not yet projected". Only WebAppAuthorizationCheck runs here.
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      filterChainBuilder.addFilterAfter(webAppFilter, OAuth2RefreshTokenFilter.class);
    }

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    // Install the multi-IdP login picker (GH-269): the custom entry point trips
    // DefaultLoginPageConfigurer's gate, so the picker would otherwise be dropped and multi-IdP
    // deployments 302 to /login -> 404. Must be added after applyCsrfConfiguration — both anchor on
    // CsrfFilter and the stable sort makes insertion order the tie-break, so the CSRF header filter
    // writes before the picker commits the response.
    final var loginPickerFilter =
        oidcLoginPickerProvider.getIfAvailable(
            () ->
                LoginLinksBuilder.defaultOauth2LoginPickerFilter(
                    clientRegistrationRepository, loginUrl));
    filterChainBuilder.addFilterAfter(loginPickerFilter, CsrfFilter.class);

    return filterChainBuilder.build();
  }

  /**
   * Builds the HTTP-Basic form-login webapp chain for the primary (non-scoped) webapp paths.
   * Matchers, login URL, and logout URL are derived from the injected {@link SecurityPathPort} and
   * CSL constants.
   */
  public SecurityFilterChain buildBasicWebappChain(final HttpSecurity http) throws Exception {

    final var matchers = pathPort.webappPaths();
    final var loginUrl = LOGIN_URL;
    final var logoutUrl = LOGOUT_URL;

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .cors(AbstractHttpConfigurer::disable)
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

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  /**
   * Builds the per-scope webapp chain for the given {@code basePath} and {@code authentication}
   * configuration. Derives prefixed matchers and endpoint URLs from the basePath and delegates to
   * either the OIDC or BASIC chain builder depending on the authentication method.
   *
   * <p>For OIDC scopes, builds a per-scope OAuth2 client stack: an {@link
   * InMemoryClientRegistrationRepository} from the descriptor's providers, an {@link
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
      final String scopedSessionCookieName)
      throws Exception {
    Objects.requireNonNull(http, "http must not be null");
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(authentication, "authentication must not be null");
    Objects.requireNonNull(pathPort, "pathPort must not be null");
    Objects.requireNonNull(properties, "properties must not be null");
    Objects.requireNonNull(authentication.getMethod(), "authentication.method must not be null");
    Objects.requireNonNull(sessionRepositoryFilter, "sessionRepositoryFilter must not be null");
    Objects.requireNonNull(scopedSessionCookieName, "scopedSessionCookieName must not be null");
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
              http, prefix, authentication, sessionRepositoryFilter, scopedSessionCookieName);
      case BASIC ->
          buildBasicWebappChainInternal(
              http, prefix, sessionRepositoryFilter, scopedSessionCookieName);
      default ->
          throw new IllegalStateException(
              "Unsupported authentication method: " + authentication.getMethod());
    };
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
    final var entryPoints = new LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>();
    entryPoints.put(new RequestHeaderRequestMatcher("Authorization"), bearerEntryPoint);
    final var delegatingEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
    delegatingEntryPoint.setDefaultEntryPoint(oauthRedirectEntryPoint);
    return delegatingEntryPoint;
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
      final String scopedSessionCookieName)
      throws Exception {

    final var matchers = pathPort.webappPaths().stream().map(p -> prefix + p).toList();
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
        new InMemoryClientRegistrationRepository(
            scopedClientRegistrationFactory.createFromProviderMap(providerMap));
    final var authorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();
    final var authorizedClientManager =
        authorizedClientManagerFactory.create(
            clientRegistrationRepository, authorizedClientRepository);
    final var scopedResolver =
        new CamundaOidcAuthorizationRequestResolver(
            clientRegistrationRepository, providerMap, authorizationBaseUri);
    final var scopedPicker =
        LoginLinksBuilder.defaultOauth2LoginPickerFilter(
            clientRegistrationRepository, loginUrl, prefix);

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
                            oidcWebappAuthenticationEntryPoint(
                                clientRegistrationRepository, loginUrl, authorizationBaseUri))
                        .accessDeniedHandler(authFailureHandler))
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            // No oauth2ResourceServer on the webapp chain: it authenticates users interactively via
            // oauth2Login and serves them from the session. Bearer/JWT (client-credentials, direct
            // API access) is the API chain's responsibility (ADR-0023); a bearer token presented to
            // a webapp path falls through to the delegating entry point below, which returns 401.
            .oauth2Login(
                oauthLogin -> {
                  oauthLogin
                      .clientRegistrationRepository(clientRegistrationRepository)
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
                          pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, prefix));
                  logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
                });

    // Refresh expired access tokens transparently after AuthorizationFilter; the logout handler
    // force-logs-out users whose refresh token has also expired.
    final var logoutHandler =
        new CompositeLogoutHandler(
            pathScopedCookieClearingLogoutHandler(scopedSessionCookieName, prefix),
            pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, prefix),
            new SecurityContextLogoutHandler());
    filterChainBuilder.addFilterAfter(
        new OAuth2RefreshTokenFilter(
            authorizedClientRepository, authorizedClientManager, logoutHandler),
        AuthorizationFilter.class);

    // AdminUserCheckFilter is intentionally NOT wired on the OIDC chain (ADR-0011, GH-189): under
    // OIDC, admin provisioning is driven by IdP claims, and the filter cannot tell "no admin yet"
    // from "membership not yet projected". Only WebAppAuthorizationCheck runs here.
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      filterChainBuilder.addFilterAfter(webAppFilter, OAuth2RefreshTokenFilter.class);
    }

    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, prefix);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    // Install the multi-IdP login picker (GH-269): the custom entry point trips
    // DefaultLoginPageConfigurer's gate, so the picker would otherwise be dropped and multi-IdP
    // deployments 302 to /login -> 404. Must be added after applyCsrfConfiguration — both anchor on
    // CsrfFilter and the stable sort makes insertion order the tie-break, so the CSRF header filter
    // writes before the picker commits the response.
    filterChainBuilder.addFilterAfter(scopedPicker, CsrfFilter.class);

    return filterChainBuilder.build();
  }

  private SecurityFilterChain buildBasicWebappChainInternal(
      final HttpSecurity http,
      final String prefix,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String scopedSessionCookieName)
      throws Exception {

    final var matchers = pathPort.webappPaths().stream().map(p -> prefix + p).toList();
    final var loginUrl = prefix + CamundaSecurityFilterChainConstants.LOGIN_URL;
    final var logoutUrl = prefix + CamundaSecurityFilterChainConstants.LOGOUT_URL;

    // Install the per-scope session filter before the security context filter.
    http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);

    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .cors(AbstractHttpConfigurer::disable)
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
                            pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, prefix)))
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler));

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

    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, prefix);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

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
