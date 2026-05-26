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
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.SESSION_COOKIE;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.filter.OAuth2RefreshTokenFilter;
import io.camunda.security.spring.filter.WebAppAuthorizationCheckFilter;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.LoggingAuthenticationFailureHandler;
import io.camunda.security.spring.handler.OAuth2AuthenticationExceptionHandler;
import io.camunda.security.spring.oidc.OidcTokenEndpointCustomizer;
import java.util.LinkedHashMap;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Filter chain that protects webapp UI paths with OIDC OAuth2 login and supports session-based
 * navigation, transparent access-token refresh, and logout. The OAuth2 authorization request
 * resolver defaults to Spring Security's default; hosts that register a bean of type {@link
 * OAuth2AuthorizationRequestResolver} override that default through the {@link ObjectProvider} hook
 * on {@link #oidcWebappSecurityFilterChain}.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcWebappSecurityConfiguration {

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain oidcWebappSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final ClientRegistrationRepository clientRegistrationRepository,
      final JwtDecoder jwtDecoder,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final OAuth2AuthorizedClientManager authorizedClientManager,
      final ObjectProvider<OidcTokenEndpointCustomizer> tokenEndpointCustomizerProvider,
      final ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
      final ObjectProvider<OidcUserService> oidcUserServiceProvider,
      final ObjectProvider<OAuth2AuthorizationRequestResolver> authorizationRequestResolverProvider,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final ObjectProvider<WebAppAuthorizationCheckFilter> webAppAuthorizationFilterProvider,
      final ObjectProvider<DefaultLoginPageGeneratingFilter> oidcLoginPickerProvider,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {

    final var filterChainBuilder =
        http.securityMatcher(pathPort.webappPaths().toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(
                            pathPort.unauthenticatedWebappPaths().toArray(String[]::new))
                        .permitAll()
                        // Permit LOGIN_URL and LOGOUT_URL explicitly even though Spring
                        // Security's default oauth2Login filters typically intercept them
                        // before the authorization rule evaluates:
                        //
                        //   - GET /login is normally handled by DefaultLoginPageGeneratingFilter
                        //     (registered by oauth2Login() when no custom loginPage is set),
                        //     which renders the auto-generated provider-selection page and
                        //     terminates the chain before AuthorizationFilter runs.
                        //   - POST /logout is handled by LogoutFilter for the same reason.
                        //
                        // That's how the legacy host chains in OC and Hub avoided a redirect
                        // loop without needing explicit permitAll on these paths. We register
                        // them defensively for two cases the implicit handling does not cover:
                        //
                        //   1. The delegating entry point falls back to LOGIN_URL for
                        //      multi-IdP deployments. If a host ever registers a custom
                        //      loginPage("/login") backed by its own controller,
                        //      DefaultLoginPageGeneratingFilter drops out and an anonymous
                        //      GET /login would otherwise re-trigger the entry point and
                        //      redirect to /login forever.
                        //   2. Mirrors the basic-auth chain's permittedPaths shape and keeps
                        //      logout symmetric, so the matcher set is independent of which
                        //      framework filters happen to be active.
                        .requestMatchers(LOGIN_URL, LOGOUT_URL)
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            oidcWebappAuthenticationEntryPoint(clientRegistrationRepository))
                        .accessDeniedHandler(authFailureHandler))
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer(
                oauth2 -> {
                  oauth2
                      .jwt(jwt -> jwt.decoder(jwtDecoder))
                      .withObjectPostProcessor(postProcessBearerTokenFailureHandler());
                  resourceServerCustomizers
                      .orderedStream()
                      .forEach(customizer -> customizer.customize(oauth2));
                })
            .oauth2Login(
                oauthLogin -> {
                  oauthLogin
                      .clientRegistrationRepository(clientRegistrationRepository)
                      .authorizedClientRepository(authorizedClientRepository)
                      .redirectionEndpoint(
                          redirectionEndpoint -> redirectionEndpoint.baseUri(REDIRECT_URI))
                      .failureHandler(new OAuth2AuthenticationExceptionHandler());
                  tokenEndpointCustomizerProvider.ifAvailable(oauthLogin::tokenEndpoint);
                  oidcUserServiceProvider.ifAvailable(
                      service -> oauthLogin.userInfoEndpoint(c -> c.oidcUserService(service)));
                  // Hosts can override the authorization-request resolver to inject custom
                  // per-client behaviour (e.g. multi-IdP redirects, additional query parameters
                  // such as RFC 8707 `resource`). Falls back to Spring Security's default when
                  // no host bean is registered.
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
                      .logoutUrl(LOGOUT_URL)
                      .deleteCookies(SESSION_COOKIE, X_CSRF_TOKEN)
                      .invalidateHttpSession(true);
                  logoutSuccessHandlerProvider.ifAvailable(logout::logoutSuccessHandler);
                });

    // Register the refresh token filter after AuthorizationFilter so expired access tokens are
    // transparently refreshed before downstream filters see them. The filter needs a LogoutHandler
    // to force-logout users whose refresh tokens have also expired.
    final var logoutHandler =
        new CompositeLogoutHandler(
            new CookieClearingLogoutHandler(SESSION_COOKIE, X_CSRF_TOKEN),
            new SecurityContextLogoutHandler());
    filterChainBuilder.addFilterAfter(
        new OAuth2RefreshTokenFilter(
            authorizedClientRepository, authorizedClientManager, logoutHandler),
        AuthorizationFilter.class);

    // The admin-user setup filter is intentionally NOT wired into the OIDC chain (see ADR-0011
    // and GH-189): under OIDC, admin provisioning is driven by IdP claims and mapping rules, and
    // the filter has no signal that distinguishes "no admin yet" from "this user's membership
    // has not been projected yet" — so a freshly IdP-authenticated user would otherwise be
    // 302'd to /admin/setup. WebAppAuthorizationCheck sits directly after the refresh-token
    // filter when present.
    final var webAppFilter = webAppAuthorizationFilterProvider.getIfAvailable();
    if (webAppFilter != null) {
      filterChainBuilder.addFilterAfter(webAppFilter, OAuth2RefreshTokenFilter.class);
    }

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    // DefaultLoginPageConfigurer's `entryPoint == null` gate is tripped by our custom entry point,
    // so the picker is silently dropped and multi-IdP deployments 302 to /login and 404 (GH-269).
    // Must follow applyCsrfConfiguration: both filters anchor to CsrfFilter via addFilterAfter and
    // stable sort makes insertion order the tie-break — the CSRF header filter must be inserted
    // first so it writes its header before the picker commits the response.
    final var loginPickerFilter =
        oidcLoginPickerProvider.getIfAvailable(
            () -> LoginLinksBuilder.defaultOauth2LoginPickerFilter(clientRegistrationRepository));
    filterChainBuilder.addFilterAfter(loginPickerFilter, CsrfFilter.class);

    return filterChainBuilder.build();
  }

  /**
   * Delegating entry point: requests carrying an {@code Authorization} header receive a 401 via
   * {@link BearerTokenAuthenticationEntryPoint}; everything else (browser navigations) is
   * redirected to a login URL that depends on the configured client registrations.
   *
   * <p>When the {@link ClientRegistrationRepository} exposes exactly one registration the redirect
   * targets {@code /oauth2/authorization/{id}} so the browser is sent straight to the IdP. When
   * multiple registrations are present (multi-IdP), the redirect targets {@link
   * CamundaSecurityFilterChainConstants#LOGIN_URL} so the host can render a provider-selection
   * page. When the repository is not iterable (host-supplied implementation that does not extend
   * {@link Iterable}) the redirect falls back to {@code /oauth2/authorization/oidc} for backwards
   * compatibility.
   *
   * <p>Required because both {@code oauth2ResourceServer} and {@code oauth2Login} register their
   * own entry points, and in Spring Security 7.x the resource server's takes precedence — causing
   * browser requests to receive 401 instead of a 302 redirect to the IdP.
   */
  private static AuthenticationEntryPoint oidcWebappAuthenticationEntryPoint(
      final ClientRegistrationRepository clientRegistrationRepository) {
    final var bearerEntryPoint = new BearerTokenAuthenticationEntryPoint();
    final var oauthRedirectEntryPoint =
        new LoginUrlAuthenticationEntryPoint(
            resolveOauthRedirectTarget(clientRegistrationRepository));
    final var entryPoints = new LinkedHashMap<RequestMatcher, AuthenticationEntryPoint>();
    entryPoints.put(new RequestHeaderRequestMatcher("Authorization"), bearerEntryPoint);
    final var delegatingEntryPoint = new DelegatingAuthenticationEntryPoint(entryPoints);
    delegatingEntryPoint.setDefaultEntryPoint(oauthRedirectEntryPoint);
    return delegatingEntryPoint;
  }

  private static String resolveOauthRedirectTarget(
      final ClientRegistrationRepository clientRegistrationRepository) {
    final var defaultTarget = "/oauth2/authorization/" + OIDC_REGISTRATION_ID;
    if (!(clientRegistrationRepository instanceof final Iterable<?> iterable)) {
      return defaultTarget;
    }
    final var iterator = iterable.iterator();
    if (!iterator.hasNext()) {
      return defaultTarget;
    }
    final Object first = iterator.next();
    if (iterator.hasNext()) {
      // Multiple client registrations: redirect to the host's login page so users can pick a
      // provider.
      return LOGIN_URL;
    }
    if (first
        instanceof
        final org.springframework.security.oauth2.client.registration.ClientRegistration
                registration) {
      return "/oauth2/authorization/" + registration.getRegistrationId();
    }
    return defaultTarget;
  }

  private static ObjectPostProcessor<BearerTokenAuthenticationFilter>
      postProcessBearerTokenFailureHandler() {
    return new ObjectPostProcessor<>() {
      @Override
      public <O extends BearerTokenAuthenticationFilter> O postProcess(final O filter) {
        final var defaultFailureHandler =
            new AuthenticationEntryPointFailureHandler(new BearerTokenAuthenticationEntryPoint());
        final var loggingFailureHandler =
            new LoggingAuthenticationFailureHandler(defaultFailureHandler);
        filter.setAuthenticationFailureHandler(loggingFailureHandler);
        return filter;
      }
    };
  }
}
