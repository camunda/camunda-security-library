/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.LoggingAuthenticationFailureHandler;
import io.camunda.security.spring.security.HttpsRedirectCustomizer;
import io.camunda.security.spring.security.OidcResourceServerCustomizer;
import io.camunda.security.spring.security.SecurityFilterChainSupport;
import java.util.Collection;
import java.util.Objects;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.session.web.http.SessionRepositoryFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Reusable builder that is the single source of truth for the CSL API filter-chain shape. Both
 * CSL's own API chains and per-scope chains are assembled by delegating to this builder, ensuring
 * identical configuration.
 *
 * <p>The builder produces either an OIDC resource-server chain or an HTTP Basic chain, selected by
 * the caller. For scoped chains the matchers are derived from {@link SecurityPathPort#apiPaths()}
 * and {@link SecurityPathPort#unprotectedApiPaths()}, each entry prefixed with the scope's {@code
 * basePath}. The API surface is host-defined, not fixed to any particular path such as {@code
 * /v2/**}.
 */
public final class ScopedApiSecurityChainBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(ScopedApiSecurityChainBuilder.class);

  private final CamundaSecurityLibraryProperties properties;
  private final AuthFailureHandler authFailureHandler;
  private final SecurityPathPort pathPort;
  private final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers;
  private final CorsConfigurationSource corsSource;
  private final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers;

  public ScopedApiSecurityChainBuilder(
      final CamundaSecurityLibraryProperties properties,
      final AuthFailureHandler authFailureHandler,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final CorsConfigurationSource corsSource,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers) {
    this.properties = properties;
    this.authFailureHandler = authFailureHandler;
    this.pathPort = pathPort;
    this.resourceServerCustomizers = resourceServerCustomizers;
    this.corsSource = corsSource;
    this.httpsRedirectCustomizers = httpsRedirectCustomizers;
  }

  /**
   * Builds an OIDC resource-server API chain over the given matchers, using the supplied decoder.
   * When a {@code sessionRepositoryFilter} is provided it is installed before {@link
   * SecurityContextHolderFilter} so that an existing session's {@code SecurityContext} is restored;
   * bearer validation remains unchanged and {@link SessionCreationPolicy#NEVER} is retained so no
   * session is created by this chain.
   */
  public SecurityFilterChain buildOidcApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    return buildOidcApiChainWith(
        http,
        matchers,
        unprotectedMatchers,
        jwtDecoder,
        sessionRepositoryFilter,
        null,
        X_CSRF_TOKEN);
  }

  private SecurityFilterChain buildOidcApiChainWith(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String csrfCookiePath,
      final String csrfCookieName)
      throws Exception {
    Objects.requireNonNull(jwtDecoder, "jwtDecoder must not be null");
    LOG.debug(
        "Building OIDC API chain for matchers={}, unprotected={}", matchers, unprotectedMatchers);
    if (sessionRepositoryFilter != null) {
      // Install the per-scope session filter before SecurityContextHolderFilter so the
      // Spring-Session-backed HttpSession is available when the security context is read.
      http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
    }
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(unprotectedMatchers.toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .oauth2ResourceServer(
                oauth2 -> {
                  oauth2
                      .jwt(jwt -> jwt.decoder(jwtDecoder))
                      .accessDeniedHandler(authFailureHandler)
                      .withObjectPostProcessor(postProcessBearerTokenFailureHandler());
                  resourceServerCustomizers
                      .orderedStream()
                      .forEach(customizer -> customizer.customize(oauth2));
                })
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            .requestCache(cache -> cache.requestCache(new NullRequestCache()))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .oauth2Login(AbstractHttpConfigurer::disable)
            .oidcLogout(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable);
    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, csrfCookiePath, csrfCookieName);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  /**
   * Builds an HTTP Basic API chain over the given matchers. When a {@code sessionRepositoryFilter}
   * is provided it is installed before {@link SecurityContextHolderFilter} so that an existing
   * session's {@code SecurityContext} is restored; {@link SessionCreationPolicy#NEVER} is retained
   * so no session is created by this chain.
   */
  public SecurityFilterChain buildBasicApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    return buildBasicApiChainWith(
        http, matchers, unprotectedMatchers, sessionRepositoryFilter, null, X_CSRF_TOKEN);
  }

  private SecurityFilterChain buildBasicApiChainWith(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final SessionRepositoryFilter<?> sessionRepositoryFilter,
      final String csrfCookiePath,
      final String csrfCookieName)
      throws Exception {
    LOG.debug(
        "Building Basic API chain for matchers={}, unprotected={}", matchers, unprotectedMatchers);
    if (sessionRepositoryFilter != null) {
      // Install the per-scope session filter before SecurityContextHolderFilter so the
      // Spring-Session-backed HttpSession is available when the security context is read.
      http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
    }
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(unprotectedMatchers.toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .httpBasic(org.springframework.security.config.Customizer.withDefaults())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            .requestCache(cache -> cache.requestCache(new NullRequestCache()));

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder, properties, pathPort, csrfCookiePath, csrfCookieName);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  /**
   * Builds the API chain for a single scope, selected by {@code authentication.getMethod()}. The
   * security matchers and unprotected matchers are derived from the host's {@link
   * SecurityPathPort}: each entry from {@link SecurityPathPort#apiPaths()} and {@link
   * SecurityPathPort#unprotectedApiPaths()} is prefixed with the scope's {@code basePath}. The API
   * surface is therefore host-defined — for example, when the host's {@code apiPaths()} is {@code
   * {"/v2/**"}}, the scoped matcher becomes {@code basePath + "/v2/**"}; a host with {@code
   * {"/api/**"}} produces {@code basePath + "/api/**"} instead.
   *
   * <p>For OIDC the per-scope decoder is obtained from the supplier (so the builder stays decoupled
   * from decoder construction); for BASIC no decoder is needed.
   *
   * <p>When a {@code sessionRepositoryFilter} is provided it is installed before {@link
   * SecurityContextHolderFilter} so the per-scope Spring Session is consulted on each request.
   * Bearer validation is unchanged; {@link SessionCreationPolicy#NEVER} is retained so this chain
   * never creates a session of its own.
   */
  public SecurityFilterChain buildScopedApiChain(
      final HttpSecurity http,
      final String basePath,
      final AuthenticationConfiguration authentication,
      final Supplier<JwtDecoder> oidcDecoderSupplier,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var method =
        Objects.requireNonNull(
            authentication.getMethod(), "authentication.method must not be null");
    Objects.requireNonNull(oidcDecoderSupplier, "oidcDecoderSupplier must not be null");
    Objects.requireNonNull(http, "http must not be null");
    final var prefix = BasePaths.normalize(basePath, "basePath");
    if (prefix.isEmpty()) {
      throw new IllegalArgumentException(
          "basePath must not be the root path '/' for a scoped chain, but was: " + basePath);
    }
    final var matchers = pathPort.apiPaths().stream().map(p -> prefix + p).toList();
    final var unprotected = pathPort.unprotectedApiPaths().stream().map(p -> prefix + p).toList();
    final var csrfCookieName = ScopedSecurityChainRegistrar.csrfCookieName(basePath);
    return switch (method) {
      case OIDC -> {
        final var decoder =
            Objects.requireNonNull(
                oidcDecoderSupplier.get(), "oidcDecoderSupplier must not return a null JwtDecoder");
        yield buildOidcApiChainWith(
            http,
            matchers,
            unprotected,
            decoder,
            sessionRepositoryFilter,
            basePath,
            csrfCookieName);
      }
      case BASIC ->
          buildBasicApiChainWith(
              http, matchers, unprotected, sessionRepositoryFilter, basePath, csrfCookieName);
      default -> throw new IllegalStateException("Unsupported authentication method: " + method);
    };
  }

  /**
   * Convenience overload of {@link #buildOidcApiChain(HttpSecurity, Collection, Collection,
   * JwtDecoder, SessionRepositoryFilter)} that installs no SessionRepositoryFilter.
   */
  public SecurityFilterChain buildOidcApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder)
      throws Exception {
    return buildOidcApiChain(http, matchers, unprotectedMatchers, jwtDecoder, null);
  }

  /**
   * Convenience overload of {@link #buildBasicApiChain(HttpSecurity, Collection, Collection,
   * SessionRepositoryFilter)} that installs no SessionRepositoryFilter.
   */
  public SecurityFilterChain buildBasicApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers)
      throws Exception {
    return buildBasicApiChain(http, matchers, unprotectedMatchers, null);
  }

  /**
   * Convenience overload of {@link #buildScopedApiChain(HttpSecurity, String,
   * AuthenticationConfiguration, Supplier, SessionRepositoryFilter)} that installs no
   * SessionRepositoryFilter.
   */
  public SecurityFilterChain buildScopedApiChain(
      final HttpSecurity http,
      final String basePath,
      final AuthenticationConfiguration authentication,
      final Supplier<JwtDecoder> oidcDecoderSupplier)
      throws Exception {
    return buildScopedApiChain(http, basePath, authentication, oidcDecoderSupplier, null);
  }

  /**
   * Builds a permit-all (unprotected) API chain over the given scope's path matchers. Mirrors
   * {@link io.camunda.security.spring.security.UnprotectedApiSecurityConfiguration} but scoped to
   * {@code basePath}: the security matchers are derived the same way as in {@link
   * #buildScopedApiChain} — each entry from {@link SecurityPathPort#apiPaths()} prefixed with
   * {@code basePath}. No decoder or credential check is needed; all requests to the scoped paths
   * are permitted unconditionally.
   *
   * <p>Used when {@code camunda.security.authentication.unprotected-api=true}: in that mode the
   * primary API chain is already permit-all, and contributed scoped chains must follow suit so the
   * whole API surface behaves consistently.
   */
  public SecurityFilterChain buildUnprotectedScopedApiChain(
      final HttpSecurity http, final String basePath) throws Exception {
    Objects.requireNonNull(http, "http must not be null");
    Objects.requireNonNull(basePath, "basePath must not be null");
    final var prefix = BasePaths.normalize(basePath, "basePath");
    if (prefix.isEmpty()) {
      throw new IllegalArgumentException(
          "basePath must not be the root path '/' for a scoped chain, but was: " + basePath);
    }
    final var matchers = pathPort.apiPaths().stream().map(p -> prefix + p).toList();
    LOG.debug(
        "Building unprotected scoped API chain for basePath={}, matchers={}", basePath, matchers);
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .exceptionHandling(eh -> eh.accessDeniedHandler(authFailureHandler))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.applyCsrfConfiguration(
        filterChainBuilder,
        properties,
        pathPort,
        basePath,
        ScopedSecurityChainRegistrar.csrfCookieName(basePath));
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
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
