/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.LOGIN_URL;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNHANDLED;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_UNPROTECTED;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.cors.NoOpCorsConfigurationSource;
import io.camunda.security.spring.csrf.CsrfProtectionRequestMatcher;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Always-on filter chains: unprotected paths (highest priority) and a catch-all deny chain (lowest
 * priority). Activates Spring Security's web security infrastructure via {@link EnableWebSecurity}.
 *
 * <p>With CSRF enabled, the unprotected chain never serves state-changing requests to {@code
 * /login}; they fall through to the CSRF-enforcing chain, or to a deny chain if none claims them
 * (ADR-0032).
 */
@Configuration
@EnableWebSecurity
public class BaseSecurityConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(BaseSecurityConfiguration.class);

  @Bean
  @Order(ORDER_UNPROTECTED)
  public SecurityFilterChain unprotectedPathsSecurityFilterChain(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers,
      final ObjectProvider<SecurityHeadersCustomizer> securityHeadersCustomizers)
      throws Exception {
    final var unprotectedPaths = pathPort.unprotectedPaths();
    final var pathMatcherBuilder = SecurityFilterChainSupport.pathMatcherBuilder(http);
    final var loginOverlaps =
        SecurityFilterChainSupport.findUnprotectedPathOverlaps(unprotectedPaths, Set.of(LOGIN_URL));
    final var csrfEnabled = properties.getCsrf().isEnabled();
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher(
                new AndRequestMatcher(
                    CsrfProtectionRequestMatcher.buildPathsMatcher(
                        pathMatcherBuilder, unprotectedPaths),
                    new NegatedRequestMatcher(
                        excludedFromUnprotectedChain(
                            pathMatcherBuilder, unprotectedPaths, csrfEnabled))))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    // Best-effort (default parser semantics), so it only drives logging, never routing or token
    // issuance. With CSRF disabled nothing is rerouted, so there is nothing to log.
    if (csrfEnabled && !loginOverlaps.isEmpty()) {
      logLoginOverlap(SecurityFilterChainSupport.firstMatchingPattern(unprotectedPaths, LOGIN_URL));
    }
    SecurityFilterChainSupport.applyLoginTokenIssuance(
        filterChainBuilder, properties, pathMatcherBuilder);

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  private static void logLoginOverlap(final String overlappingPattern) {
    LOG.info(
        "SecurityPathPort#unprotectedPaths() pattern '{}' overlaps the login endpoint '{}':"
            + " GET/HEAD/OPTIONS/TRACE requests to it are served unauthenticated, while"
            + " state-changing requests are passed on to the next chain: an API or webapp chain"
            + " covering '{}' (which enforces CSRF), otherwise a deny chain (the catch-all, or with"
            + " it disabled the unclaimed-login guard).",
        overlappingPattern,
        LOGIN_URL,
        LOGIN_URL);
  }

  /**
   * The requests the unprotected chain passes on: state-changing requests to {@code /login} it
   * would otherwise claim. Built with the chain's {@code builder}, otherwise a servlet {@code
   * basePath} would open a gap. Matches nothing when CSRF is disabled: there is no check to route
   * to, so {@code /login} stays fully unprotected as declared.
   */
  private static RequestMatcher excludedFromUnprotectedChain(
      final PathPatternRequestMatcher.Builder builder,
      final Set<String> unprotectedPaths,
      final boolean csrfEnabled) {
    if (!csrfEnabled) {
      return request -> false;
    }
    return new AndRequestMatcher(
        CsrfProtectionRequestMatcher.buildPathsMatcher(builder, unprotectedPaths),
        SecurityFilterChainSupport.stateChangingRequestTo(builder, Set.of(LOGIN_URL)));
  }

  /**
   * Catch-all deny chain (lowest priority). A host that installs its own {@code /**} catch-all
   * webapp chain (e.g. Optimize, which reuses the OIDC webapp chain with a {@code /**} matcher, see
   * ADR-0018) must suppress this bean, otherwise Spring Security rejects the two duplicate {@code
   * /**} matchers at startup. Set {@code
   * camunda.security.authentication.catch-all-unhandled-paths-enabled=false} to suppress it.
   * Enabled by default so existing hosts are unaffected.
   *
   * <p><b>Warning:</b> only disable this when another chain claims all otherwise-unhandled paths
   * (the host's own {@code /**} catch-all). Disabling it without such a chain leaves unhandled
   * paths unsecured.
   */
  @Bean
  @Order(ORDER_UNHANDLED)
  @ConditionalOnProperty(
      name = "camunda.security.authentication.catch-all-unhandled-paths-enabled",
      havingValue = "true",
      matchIfMissing = true)
  public SecurityFilterChain protectedUnhandledPathsSecurityFilterChain(
      final HttpSecurity http,
      final ObjectProvider<CorsConfigurationSource> corsSourceProvider,
      final ObjectProvider<HttpsRedirectCustomizer> httpsRedirectCustomizers)
      throws Exception {
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher("/**")
            .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
            .exceptionHandling(BaseSecurityConfiguration::respondNotFound)
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    // Intentional: CORS and HTTPS redirect hooks apply to the catch-all chain so that a
    // host-provided CorsConfigurationSource handles preflight OPTIONS requests even for paths that
    // don't match any other chain (otherwise a broad "/**" CORS mapping would silently miss them).
    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);

    return filterChainBuilder.build();
  }

  /**
   * Stands in for the catch-all deny chain when it is disabled: rejects (404) the state-changing
   * {@code /login} requests the unprotected chain passes on and no earlier API or webapp chain
   * claims, which would otherwise reach no security chain and skip CSRF (ADR-0032). Its matcher is
   * built exactly like the unprotected chain's exclusion, so the two cannot disagree on the host's
   * path builder (servlet {@code basePath}, parser). A host chain that should serve these requests
   * must be ordered before {@code ORDER_UNHANDLED}.
   */
  @Bean
  @Order(ORDER_UNHANDLED)
  @ConditionalOnProperty(
      name = "camunda.security.authentication.catch-all-unhandled-paths-enabled",
      havingValue = "false")
  public SecurityFilterChain unclaimedLoginGuardSecurityFilterChain(
      final HttpSecurity http,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    final var unprotectedPaths = pathPort.unprotectedPaths();
    final var csrfEnabled = properties.getCsrf().isEnabled();
    if (csrfEnabled && !unprotectedPaths.isEmpty()) {
      LOG.info(
          "Catch-all chain disabled: state-changing requests to '{}' that no API or webapp chain"
              + " claims are rejected with 404 by unclaimedLoginGuardSecurityFilterChain.",
          LOGIN_URL);
    }
    return http.securityMatcher(
            excludedFromUnprotectedChain(
                SecurityFilterChainSupport.pathMatcherBuilder(http), unprotectedPaths, csrfEnabled))
        .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
        .exceptionHandling(BaseSecurityConfiguration::respondNotFound)
        .csrf(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .anonymous(AbstractHttpConfigurer::disable)
        .build();
  }

  private static void respondNotFound(final ExceptionHandlingConfigurer<HttpSecurity> eh) {
    eh.authenticationEntryPoint(
            (request, response, authenticationException) ->
                response.sendError(HttpServletResponse.SC_NOT_FOUND))
        .accessDeniedHandler(
            (request, response, accessDeniedException) ->
                response.sendError(HttpServletResponse.SC_NOT_FOUND));
  }
}
