/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.OIDC_REGISTRATION_ID;
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
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import io.camunda.security.spring.scope.ScopedApiSecurityChainBuilder;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.function.Consumer;
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
 * BasicAuthWebappSecurityConfiguration} delegate here; the same methods are used to assemble
 * per-scope webapp chains by passing {@code basePath}-prefixed matchers and endpoint URLs.
 */
public final class ScopedWebappSecurityChainBuilder {

  private final ScopedClientRegistrationFactory clientRegistrationFactory;

  /** No-arg constructor for backward compatibility with primary webapp configuration classes. */
  public ScopedWebappSecurityChainBuilder() {
    this(new ScopedClientRegistrationFactory());
  }

  public ScopedWebappSecurityChainBuilder(
      final ScopedClientRegistrationFactory clientRegistrationFactory) {
    this.clientRegistrationFactory = clientRegistrationFactory;
  }

  /**
   * Builds the OIDC oauth2Login webapp chain. Body moved verbatim from {@code
   * OidcWebappSecurityConfiguration#oidcWebappSecurityFilterChain}; the {@code matchers}, {@code
   * unauthenticatedMatchers}, {@code loginUrl}, {@code logoutUrl} and {@code redirectUri} were
   * inlined constants there and are parameters here.
   */
  public SecurityFilterChain buildOidcWebappChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unauthenticatedMatchers,
      final String loginUrl,
      final String logoutUrl,
      final String redirectUri,
      final AuthFailureHandler authFailureHandler,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    return buildOidcWebappChainInternal(
        http,
        matchers,
        unauthenticatedMatchers,
        loginUrl,
        logoutUrl,
        redirectUri,
        authFailureHandler,
        clientRegistrationRepository,
        authorizedClientRepository,
        authorizedClientManager,
        tokenEndpointCustomizerProvider,
        logoutSuccessHandlerProvider,
        oidcUserServiceProvider,
        authorizationRequestResolverProvider,
        webAppAuthorizationFilterProvider,
        oidcLoginPickerProvider,
        properties,
        pathPort,
        null,
        null,
        null,
        null,
        "/oauth2/authorization");
  }

  /**
   * Builds the HTTP-Basic form-login webapp chain. Body moved verbatim from {@code
   * BasicAuthWebappSecurityConfiguration#basicAuthWebappSecurityFilterChain}; {@code matchers},
   * {@code loginUrl} and {@code logoutUrl} were inlined there and are parameters here.
   */
  public SecurityFilterChain buildBasicWebappChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final String loginUrl,
      final String logoutUrl,
      final AuthFailureHandler authFailureHandler,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    return buildBasicWebappChainInternal(
        http,
        matchers,
        loginUrl,
        logoutUrl,
        authFailureHandler,
        webAppAuthorizationFilterProvider,
        adminUserCheckFilterProvider,
        properties,
        pathPort,
        null,
        null,
        null,
        null);
  }

  /**
   * Builds the per-scope webapp chain for the given {@code basePath} and {@code authentication}
   * configuration. Derives prefixed matchers and endpoint URLs from the basePath and delegates to
   * either the OIDC or BASIC chain builder depending on the authentication method.
   *
   * <p>For OIDC scopes, builds a per-scope OAuth2 client stack: an {@link
   * InMemoryClientRegistrationRepository} from the descriptor's providers, an {@link
   * AuthenticatedPrincipalOAuth2AuthorizedClientRepository}, an {@link
   * OAuth2AuthorizedClientManager} via the supplied factory, and a prefix-aware {@link
   * CamundaOidcAuthorizationRequestResolver}. The login picker is also prefix-aware so its
   * authorization links point to {@code <basePath>/oauth2/authorization/<id>}.
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
      final AuthFailureHandler authFailureHandler,
      final OAuth2AuthorizedClientManagerFactory authorizedClientManagerFactory,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    final var prefix = ScopedApiSecurityChainBuilder.normalizeBasePath(basePath);
    final var matchers = pathPort.webappPaths().stream().map(p -> prefix + p).toList();
    final var unauthenticated =
        pathPort.unauthenticatedWebappPaths().stream().map(p -> prefix + p).toList();
    final var loginUrl = prefix + CamundaSecurityFilterChainConstants.LOGIN_URL;
    final var logoutUrl = prefix + CamundaSecurityFilterChainConstants.LOGOUT_URL;
    final var redirectUri = prefix + CamundaSecurityFilterChainConstants.REDIRECT_URI;

    Objects.requireNonNull(authentication.getMethod(), "authentication.method must not be null");
    return switch (authentication.getMethod()) {
      case OIDC -> {
        final var registrations = clientRegistrationFactory.create(authentication);
        final var scopeRepo = new InMemoryClientRegistrationRepository(registrations);
        final var authorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();
        final var authorizedClientManager =
            authorizedClientManagerFactory.create(scopeRepo, authorizedClientRepository);
        final var authorizationBaseUri = prefix + "/oauth2/authorization";
        final var resolver =
            new CamundaOidcAuthorizationRequestResolver(
                scopeRepo, clientRegistrationFactory.flatten(authentication), authorizationBaseUri);
        // Per-scope picker with authorization links prefixed to the scope basePath.
        final var picker =
            LoginLinksBuilder.defaultOauth2LoginPickerFilter(scopeRepo, loginUrl, prefix);
        yield buildOidcWebappChainInternal(
            http,
            matchers,
            unauthenticated,
            loginUrl,
            logoutUrl,
            redirectUri,
            authFailureHandler,
            scopeRepo,
            authorizedClientRepository,
            authorizedClientManager,
            tokenEndpointCustomizerProvider,
            logoutSuccessHandlerProvider,
            oidcUserServiceProvider,
            singletonProvider(resolver),
            webAppAuthorizationFilterProvider,
            singletonProvider(picker),
            properties,
            pathPort,
            sessionRepositoryFilter,
            basePath,
            scopedSessionCookieName,
            basePath,
            authorizationBaseUri);
      }
      case BASIC ->
          buildBasicWebappChainInternal(
              http,
              matchers,
              loginUrl,
              logoutUrl,
              authFailureHandler,
              webAppAuthorizationFilterProvider,
              adminUserCheckFilterProvider,
              properties,
              pathPort,
              sessionRepositoryFilter,
              basePath,
              scopedSessionCookieName,
              basePath);
      default ->
          throw new IllegalStateException(
              "Unsupported authentication method: " + authentication.getMethod());
    };
  }

  // Moved verbatim from OidcWebappSecurityConfiguration; package-private for unit testing.
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
      final Collection<String> matchers,
      final Collection<String> unauthenticatedMatchers,
      final String loginUrl,
      final String logoutUrl,
      final String redirectUri,
      final AuthFailureHandler authFailureHandler,
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String csrfCookiePath,
      final String scopedSessionCookieName,
      final String scopedCookiePath,
      final String authorizationBaseUri)
      throws Exception {

    // Install the per-scope session filter before the security context filter so the Spring-Session
    // backed, Path-scoped session is available throughout the chain.
    if (sessionRepositoryFilter != null) {
      http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
    }

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
                  authorizationRequestResolverProvider.ifAvailable(
                      resolver ->
                          oauthLogin.authorizationEndpoint(
                              authorization ->
                                  authorization.authorizationRequestResolver(resolver)));
                })
            .oidcLogout(oidcLogout -> {})
            .logout(
                logout -> {
                  logout.logoutUrl(logoutUrl).invalidateHttpSession(true);
                  if (scopedSessionCookieName != null) {
                    logout
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(
                                scopedSessionCookieName, scopedCookiePath))
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, scopedCookiePath));
                  } else {
                    logout.deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN);
                  }
                  logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
                });

    // Refresh expired access tokens transparently after AuthorizationFilter; the logout handler
    // force-logs-out users whose refresh token has also expired.
    final CompositeLogoutHandler logoutHandler;
    if (scopedSessionCookieName != null) {
      logoutHandler =
          new CompositeLogoutHandler(
              pathScopedCookieClearingLogoutHandler(scopedSessionCookieName, scopedCookiePath),
              pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, scopedCookiePath),
              new SecurityContextLogoutHandler());
    } else {
      logoutHandler =
          new CompositeLogoutHandler(
              new CookieClearingLogoutHandler(SESSION_COOKIE, X_CSRF_TOKEN),
              new SecurityContextLogoutHandler());
    }
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
        filterChainBuilder, properties, pathPort, csrfCookiePath);
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

  private SecurityFilterChain buildBasicWebappChainInternal(
      final HttpSecurity http,
      final Collection<String> matchers,
      final String loginUrl,
      final String logoutUrl,
      final AuthFailureHandler authFailureHandler,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<AdminUserCheckFilter> adminUserCheckFilterProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String csrfCookiePath,
      final String scopedSessionCookieName,
      final String scopedCookiePath)
      throws Exception {

    // Install the per-scope session filter before the security context filter.
    if (sessionRepositoryFilter != null) {
      http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
    }

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
                logout -> {
                  logout
                      .logoutUrl(logoutUrl)
                      .logoutSuccessHandler(
                          (request, response, authentication) ->
                              response.setStatus(HttpStatus.NO_CONTENT.value()));
                  if (scopedSessionCookieName != null) {
                    logout
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(
                                scopedSessionCookieName, scopedCookiePath))
                        .addLogoutHandler(
                            pathScopedCookieClearingLogoutHandler(X_CSRF_TOKEN, scopedCookiePath));
                  } else {
                    logout.deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN);
                  }
                })
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
        filterChainBuilder, properties, pathPort, csrfCookiePath);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  private static LogoutHandler pathScopedCookieClearingLogoutHandler(
      final String cookieName, final String cookiePath) {
    return (request, response, authentication) -> {
      final var cookie = new jakarta.servlet.http.Cookie(cookieName, "");
      cookie.setMaxAge(0);
      cookie.setPath(cookiePath);
      response.addCookie(cookie);
    };
  }

  private static <T> ObjectProvider<T> singletonProvider(final T value) {
    return new ObjectProvider<>() {
      @Override
      public T getObject() {
        return value;
      }

      @Override
      public T getObject(final Object... args) {
        return value;
      }

      @Override
      public T getIfAvailable() {
        return value;
      }

      @Override
      public T getIfUnique() {
        return value;
      }

      @Override
      public void ifAvailable(final Consumer<T> dependencyConsumer) {
        dependencyConsumer.accept(value);
      }
    };
  }
}
