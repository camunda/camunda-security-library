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
import io.camunda.security.spring.security.SecurityHeadersCustomizer;
import io.camunda.security.spring.spi.OidcApiAuthenticationEntryPoint;
import java.util.Collection;
import java.util.Objects;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
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
  private final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers;
  private final ObjectProvider<OidcApiAuthenticationEntryPoint> apiAuthenticationEntryPointProvider;

  /**
   * Delegates to the full constructor with no {@link OidcApiAuthenticationEntryPoint} provider,
   * preserving the exact {@link BearerTokenAuthenticationEntryPoint} default for callers built
   * before that hook existed (camunda-security-library#561).
   */
  public ScopedApiSecurityChainBuilder(
      final CamundaSecurityLibraryProperties properties,
      final AuthFailureHandler authFailureHandler,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final CorsConfigurationSource corsSource,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers) {
    this(
        properties,
        authFailureHandler,
        pathPort,
        resourceServerCustomizers,
        corsSource,
        httpsRedirectCustomizers,
        securityHeadersCustomizers,
        null);
  }

  public ScopedApiSecurityChainBuilder(
      final CamundaSecurityLibraryProperties properties,
      final AuthFailureHandler authFailureHandler,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final CorsConfigurationSource corsSource,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers,
      final ObjectProvider<OidcApiAuthenticationEntryPoint> apiAuthenticationEntryPointProvider) {
    this.properties = properties;
    this.authFailureHandler = authFailureHandler;
    this.pathPort = pathPort;
    this.resourceServerCustomizers = resourceServerCustomizers;
    this.corsSource = corsSource;
    this.httpsRedirectCustomizers = httpsRedirectCustomizers;
    this.securityHeadersCustomizers = securityHeadersCustomizers;
    this.apiAuthenticationEntryPointProvider = apiAuthenticationEntryPointProvider;
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
        null,
        sessionRepositoryFilter,
        null,
        X_CSRF_TOKEN);
  }

  /**
   * Builds an OIDC resource-server API chain over the given matchers, using the supplied decoder
   * and a host-supplied {@code jwtAuthenticationConverter}. A {@code null} converter preserves
   * Spring Security's default {@code JwtAuthenticationConverter} behavior — this builder never
   * calls {@code jwtAuthenticationConverter(...)} in that case, so pre-existing callers of the
   * decoder-only overload are unaffected.
   *
   * <p>See ADR-0016 for why this is a per-invocation parameter rather than a globally-registered
   * customizer bean: a single application may need multiple simultaneous chains (e.g. distinct API
   * versions), each with a different converter.
   *
   * <p>When a {@code sessionRepositoryFilter} is provided it is installed before {@link
   * SecurityContextHolderFilter} so that an existing session's {@code SecurityContext} is restored;
   * bearer validation remains unchanged and {@link SessionCreationPolicy#NEVER} is retained so no
   * session is created by this chain.
   */
  public SecurityFilterChain buildOidcApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder,
      final Converter<Jwt, Authentication> jwtAuthenticationConverter,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    return buildOidcApiChainWith(
        http,
        matchers,
        unprotectedMatchers,
        jwtDecoder,
        jwtAuthenticationConverter,
        sessionRepositoryFilter,
        null,
        X_CSRF_TOKEN);
  }

  private SecurityFilterChain buildOidcApiChainWith(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder,
      final Converter<Jwt, Authentication> jwtAuthenticationConverter,
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
            // Explicitly configuring the entry point here (rather than relying on
            // OAuth2ResourceServerConfigurer's automatic defaultAuthenticationEntryPointFor) is
            // what makes a host-registered OidcApiAuthenticationEntryPoint bean apply to *missing*
            // credentials, handled by ExceptionTranslationFilter — as opposed to the
            // ObjectPostProcessor below, which only covers a *malformed/invalid* token presented to
            // BearerTokenAuthenticationFilter directly (camunda-security-library#561).
            .exceptionHandling(
                eh -> eh.authenticationEntryPoint(resolveApiAuthenticationEntryPoint()))
            .oauth2ResourceServer(
                oauth2 -> {
                  oauth2.jwt(
                      jwt -> {
                        jwt.decoder(jwtDecoder);
                        if (jwtAuthenticationConverter != null) {
                          jwt.jwtAuthenticationConverter(
                              toAbstractAuthenticationTokenConverter(jwtAuthenticationConverter));
                        }
                      });
                  oauth2
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
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

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
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

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
    return buildScopedApiChain(
        http, basePath, authentication, oidcDecoderSupplier, () -> null, sessionRepositoryFilter);
  }

  /**
   * Overload of {@link #buildScopedApiChain(HttpSecurity, String, AuthenticationConfiguration,
   * Supplier, SessionRepositoryFilter)} that additionally accepts a per-scope {@code Converter<Jwt,
   * Authentication>} supplier for the OIDC arm. A {@code null} supplier reference is rejected
   * (mirroring {@code oidcDecoderSupplier}'s mandatory-reference treatment), but the supplier is
   * allowed to <em>return</em> {@code null} to mean "no converter override for this scope" — unlike
   * {@code oidcDecoderSupplier}, whose result must never be {@code null}. See ADR-0016.
   */
  public SecurityFilterChain buildScopedApiChain(
      final HttpSecurity http,
      final String basePath,
      final AuthenticationConfiguration authentication,
      final Supplier<JwtDecoder> oidcDecoderSupplier,
      final Supplier<Converter<Jwt, Authentication>> oidcAuthenticationConverterSupplier,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var method =
        Objects.requireNonNull(
            authentication.getMethod(), "authentication.method must not be null");
    Objects.requireNonNull(oidcDecoderSupplier, "oidcDecoderSupplier must not be null");
    Objects.requireNonNull(
        oidcAuthenticationConverterSupplier,
        "oidcAuthenticationConverterSupplier must not be null");
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
        final var converter = oidcAuthenticationConverterSupplier.get();
        yield buildOidcApiChainWith(
            http,
            matchers,
            unprotected,
            decoder,
            converter,
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
   *
   * <p>When a {@code sessionRepositoryFilter} is provided it is installed before {@link
   * SecurityContextHolderFilter} so a session minted on the scope's webapp chain is resolved here
   * too. Without it the scoped {@code camunda-session} cookie is never read: an endpoint like
   * {@code /physical-tenants/<id>/v2/authentication/me} would see an anonymous request, and CSRF
   * protection — which requires a token only when {@code request.getSession(false)} is non-null —
   * would never engage. {@link SessionCreationPolicy#NEVER} keeps this chain from creating a
   * session of its own, mirroring {@link
   * io.camunda.security.spring.security.UnprotectedApiSecurityConfiguration}.
   */
  public SecurityFilterChain buildUnprotectedScopedApiChain(
      final HttpSecurity http,
      final String basePath,
      final SessionRepositoryFilter<?> sessionRepositoryFilter)
      throws Exception {
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
    if (sessionRepositoryFilter != null) {
      // Install the per-scope session filter before SecurityContextHolderFilter so the
      // Spring-Session-backed HttpSession is available when the security context is read.
      http.addFilterBefore(sessionRepositoryFilter, SecurityContextHolderFilter.class);
    }
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .exceptionHandling(eh -> eh.accessDeniedHandler(authFailureHandler))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
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
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  /**
   * Convenience overload of {@link #buildUnprotectedScopedApiChain(HttpSecurity, String,
   * SessionRepositoryFilter)} that installs no SessionRepositoryFilter.
   */
  public SecurityFilterChain buildUnprotectedScopedApiChain(
      final HttpSecurity http, final String basePath) throws Exception {
    return buildUnprotectedScopedApiChain(http, basePath, null);
  }

  /**
   * Adapts a host-supplied {@code Converter<Jwt, Authentication>} to the {@code Converter<Jwt, ?
   * extends AbstractAuthenticationToken>} shape Spring Security's {@code
   * JwtConfigurer#jwtAuthenticationConverter} requires. Mirrors the adapter every host currently
   * has to write itself (e.g. Hub's {@code PublicApiSecurityConfiguration}) — centralizing it here
   * means hosts migrating onto this hook can delete their own copy.
   */
  private static Converter<Jwt, AbstractAuthenticationToken> toAbstractAuthenticationTokenConverter(
      final Converter<Jwt, Authentication> jwtAuthenticationConverter) {
    return jwt -> {
      final var authentication = jwtAuthenticationConverter.convert(jwt);
      if (authentication instanceof AbstractAuthenticationToken token) {
        return token;
      }
      // InvalidBearerTokenException's message reaches the client via the WWW-Authenticate
      // error_description, so it must not leak internal implementation details (e.g. the
      // Authentication implementation class name) — log the concrete type server-side instead.
      LOG.debug(
          "jwtAuthenticationConverter must return an AbstractAuthenticationToken, got: {}",
          authentication != null ? authentication.getClass().getName() : "null");
      throw new InvalidBearerTokenException("jwtAuthenticationConverter returned an invalid token");
    };
  }

  /**
   * Resolves any {@link OidcApiAuthenticationEntryPoint} bean present in the application context in
   * preference to the library's default (following the same "adopter hook with a built-in fallback"
   * pattern as {@link HttpsRedirectCustomizer}). When no provider was supplied at all (legacy 7-arg
   * constructor, camunda-security-library#561) the fallback is a fresh {@link
   * BearerTokenAuthenticationEntryPoint} directly; when a provider was supplied but no bean is
   * registered, the fallback is an {@link OidcApiAuthenticationEntryPoint} lambda delegating to
   * {@link BearerTokenAuthenticationEntryPoint#commence}. Both preserve the RFC 6750 challenge
   * pinned by {@code OidcApiWwwAuthenticateChallengeTest}.
   */
  private AuthenticationEntryPoint resolveApiAuthenticationEntryPoint() {
    return apiAuthenticationEntryPointProvider != null
        ? apiAuthenticationEntryPointProvider.getIfAvailable(
            () -> new BearerTokenAuthenticationEntryPoint()::commence)
        : new BearerTokenAuthenticationEntryPoint();
  }

  /**
   * Covers the *malformed/invalid* bearer token case: {@link BearerTokenAuthenticationFilter}
   * handles its own {@link org.springframework.security.core.AuthenticationException} rather than
   * letting it reach {@code ExceptionTranslationFilter}, so this must be wired independently of
   * {@link #resolveApiAuthenticationEntryPoint()}'s use in {@code exceptionHandling(...)} above,
   * even though both resolve the same entry point.
   */
  private ObjectPostProcessor<BearerTokenAuthenticationFilter>
      postProcessBearerTokenFailureHandler() {
    return new ObjectPostProcessor<>() {
      @Override
      public <O extends BearerTokenAuthenticationFilter> O postProcess(final O filter) {
        final var defaultFailureHandler =
            new AuthenticationEntryPointFailureHandler(resolveApiAuthenticationEntryPoint());
        final var loggingFailureHandler =
            new LoggingAuthenticationFailureHandler(defaultFailureHandler);
        filter.setAuthenticationFailureHandler(loggingFailureHandler);
        return filter;
      }
    };
  }
}
