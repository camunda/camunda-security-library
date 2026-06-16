/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.LoggingAuthenticationFailureHandler;
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
import org.springframework.security.web.savedrequest.NullRequestCache;

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

  public ScopedApiSecurityChainBuilder(
      final CamundaSecurityLibraryProperties properties,
      final AuthFailureHandler authFailureHandler,
      final SecurityPathPort pathPort,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers) {
    this.properties = properties;
    this.authFailureHandler = authFailureHandler;
    this.pathPort = pathPort;
    this.resourceServerCustomizers = resourceServerCustomizers;
  }

  /**
   * Builds an OIDC resource-server API chain over the given matchers, using the supplied decoder.
   */
  public SecurityFilterChain buildOidcApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers,
      final JwtDecoder jwtDecoder)
      throws Exception {
    Objects.requireNonNull(jwtDecoder, "jwtDecoder must not be null");
    LOG.debug(
        "Building OIDC API chain for matchers={}, unprotected={}", matchers, unprotectedMatchers);
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
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .oauth2Login(AbstractHttpConfigurer::disable)
            .oidcLogout(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  /** Builds an HTTP Basic API chain over the given matchers. */
  public SecurityFilterChain buildBasicApiChain(
      final HttpSecurity http,
      final Collection<String> matchers,
      final Collection<String> unprotectedMatchers)
      throws Exception {
    LOG.debug(
        "Building Basic API chain for matchers={}, unprotected={}", matchers, unprotectedMatchers);
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(unprotectedMatchers.toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .cors(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable)
            .httpBasic(org.springframework.security.config.Customizer.withDefaults())
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(authFailureHandler)
                        .accessDeniedHandler(authFailureHandler))
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
            .requestCache(cache -> cache.requestCache(new NullRequestCache()));

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
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
   */
  public SecurityFilterChain buildScopedApiChain(
      final HttpSecurity http,
      final String basePath,
      final AuthenticationConfiguration authentication,
      final Supplier<JwtDecoder> oidcDecoderSupplier)
      throws Exception {
    Objects.requireNonNull(basePath, "basePath must not be null");
    Objects.requireNonNull(authentication, "authentication must not be null");
    final var method =
        Objects.requireNonNull(
            authentication.getMethod(), "authentication.method must not be null");
    Objects.requireNonNull(oidcDecoderSupplier, "oidcDecoderSupplier must not be null");
    Objects.requireNonNull(http, "http must not be null");
    final var prefix = normalizeBasePath(basePath);
    final var matchers = pathPort.apiPaths().stream().map(p -> prefix + p).toList();
    final var unprotected = pathPort.unprotectedApiPaths().stream().map(p -> prefix + p).toList();
    return switch (method) {
      case OIDC -> {
        final var decoder =
            Objects.requireNonNull(
                oidcDecoderSupplier.get(), "oidcDecoderSupplier must not return a null JwtDecoder");
        yield buildOidcApiChain(http, matchers, unprotected, decoder);
      }
      case BASIC -> buildBasicApiChain(http, matchers, unprotected);
      default -> throw new IllegalStateException("Unsupported authentication method: " + method);
    };
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
    final var prefix = normalizeBasePath(basePath);
    final var matchers = pathPort.apiPaths().stream().map(p -> prefix + p).toList();
    LOG.debug(
        "Building unprotected scoped API chain for basePath={}, matchers={}", basePath, matchers);
    final var filterChainBuilder =
        http.securityMatcher(matchers.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .cors(AbstractHttpConfigurer::disable)
            .exceptionHandling(eh -> eh.accessDeniedHandler(authFailureHandler))
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCsrfConfiguration(filterChainBuilder, properties, pathPort);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());

    return filterChainBuilder.build();
  }

  /**
   * Normalizes a basePath by stripping a single trailing {@code /} when the path has more than one
   * character (so {@code "/"} is left as-is). Used by both the builder and the duplicate-detection
   * sweep in {@link ScopedSecurityChainRegistrar} to ensure {@code "/scope"} and {@code "/scope/"}
   * are treated as the same path.
   *
   * <p>Public so the webapp chain builder (in a different package) can reuse it without duplicating
   * the normalization logic.
   *
   * @param basePath the raw basePath; may be {@code null} (returned as-is)
   * @return the normalized basePath
   */
  public static String normalizeBasePath(final String basePath) {
    if (basePath == null) {
      return null;
    }
    return basePath.length() > 1 && basePath.endsWith("/")
        ? basePath.substring(0, basePath.length() - 1)
        : basePath;
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
