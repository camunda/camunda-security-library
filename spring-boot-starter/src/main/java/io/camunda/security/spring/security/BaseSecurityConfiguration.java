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
import java.util.HashSet;
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
 * <p>The unprotected chain never serves state-changing requests to {@code /login}; they fall
 * through to the CSRF-enforcing chain, and startup fails if none would claim them (ADR-0032).
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
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher(unprotectedPathsMatcher(pathMatcherBuilder, unprotectedPaths))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    // Best-effort (default parser semantics), so it only drives logging and the startup check,
    // never token issuance.
    if (!loginOverlaps.isEmpty()) {
      final var overlappingPattern =
          SecurityFilterChainSupport.firstMatchingPattern(unprotectedPaths, LOGIN_URL);
      logLoginOverlap(overlappingPattern, properties);
      rejectUnclaimedStateChangingLogin(pathPort, properties, overlappingPattern);
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

  private static void logLoginOverlap(
      final String overlappingPattern, final CamundaSecurityLibraryProperties properties) {
    final var stateChangingRouting =
        properties.getCsrf().isEnabled()
            ? "routed to the CSRF-enforcing API or webapp chain"
            : "routed to the API or webapp chain (CSRF protection is disabled)";
    LOG.info(
        "SecurityPathPort#unprotectedPaths() pattern '{}' overlaps the login endpoint '{}':"
            + " GET/HEAD/OPTIONS/TRACE requests to it are served unauthenticated, while"
            + " state-changing requests are {}.",
        overlappingPattern,
        LOGIN_URL,
        stateChangingRouting);
  }

  /**
   * State-changing {@code /login} requests are routed away from the unprotected chain. Without the
   * catch-all chain and without an API pattern or (with the webapp chain enabled) a webapp pattern
   * covering {@code /login}, they would reach no security chain and skip the CSRF check, so startup
   * fails (ADR-0032).
   */
  private static void rejectUnclaimedStateChangingLogin(
      final SecurityPathPort pathPort,
      final CamundaSecurityLibraryProperties properties,
      final String overlappingPattern) {
    if (properties.getAuthentication().isCatchAllUnhandledPathsEnabled()
        || isClaimedByApiOrWebappChain(
            pathPort, properties.getAuthentication().isWebappEnabled())) {
      return;
    }
    throw new IllegalStateException(
        "SecurityPathPort#unprotectedPaths() pattern '"
            + overlappingPattern
            + "' overlaps the login endpoint '"
            + LOGIN_URL
            + "' and camunda.security.authentication.catch-all-unhandled-paths-enabled=false,"
            + " but neither apiPaths() nor (with the webapp chain enabled) webappPaths() covers '"
            + LOGIN_URL
            + "': state-changing requests to '"
            + LOGIN_URL
            + "' would reach no security chain. Cover '"
            + LOGIN_URL
            + "' by apiPaths() or webappPaths(), enable the catch-all chain, or remove or narrow"
            + " the unprotected pattern (see ADR-0032).");
  }

  /** {@code webappPaths()} only count when the webapp chain exists. */
  private static boolean isClaimedByApiOrWebappChain(
      final SecurityPathPort pathPort, final boolean webappEnabled) {
    final var claimingPaths = new HashSet<>(pathPort.apiPaths());
    if (webappEnabled) {
      claimingPaths.addAll(pathPort.webappPaths());
    }
    return SecurityFilterChainSupport.firstMatchingPattern(claimingPaths, LOGIN_URL) != null;
  }

  /**
   * Unprotected paths minus state-changing requests to {@code /login}. Both halves use the same
   * {@code builder}, otherwise a servlet {@code basePath} would open a gap.
   */
  private static RequestMatcher unprotectedPathsMatcher(
      final PathPatternRequestMatcher.Builder builder, final Set<String> unprotectedPaths) {
    return new AndRequestMatcher(
        CsrfProtectionRequestMatcher.buildPathsMatcher(builder, unprotectedPaths),
        new NegatedRequestMatcher(
            SecurityFilterChainSupport.stateChangingRequestTo(builder, Set.of(LOGIN_URL))));
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
            .exceptionHandling(
                eh ->
                    eh.authenticationEntryPoint(
                            (request, response, authenticationException) ->
                                response.sendError(HttpServletResponse.SC_NOT_FOUND))
                        .accessDeniedHandler(
                            (request, response, accessDeniedException) ->
                                response.sendError(HttpServletResponse.SC_NOT_FOUND)))
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
}
