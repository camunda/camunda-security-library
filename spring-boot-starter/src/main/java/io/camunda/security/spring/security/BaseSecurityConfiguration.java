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
import jakarta.servlet.http.HttpServletResponse;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.PathContainer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Always-on filter chains: unprotected paths (highest priority) and a catch-all deny chain (lowest
 * priority). Activates Spring Security's web security infrastructure via {@link EnableWebSecurity}.
 */
@Configuration
@EnableWebSecurity
public class BaseSecurityConfiguration {

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
    rejectLoginPathOverlap(unprotectedPaths);
    final var corsSource = corsSourceProvider.getIfAvailable(NoOpCorsConfigurationSource::new);
    final var filterChainBuilder =
        http.securityMatcher(unprotectedPaths.toArray(String[]::new))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(AbstractHttpConfigurer::disable)
            .formLogin(AbstractHttpConfigurer::disable)
            .anonymous(AbstractHttpConfigurer::disable);

    SecurityFilterChainSupport.applyCorsConfiguration(filterChainBuilder, corsSource);
    SecurityFilterChainSupport.applyHttpsRedirectCustomizers(
        filterChainBuilder, httpsRedirectCustomizers);
    SecurityFilterChainSupport.setupSecureHeaders(filterChainBuilder, properties.getHttpHeaders());
    SecurityFilterChainSupport.applySecurityHeadersCustomizers(
        filterChainBuilder, securityHeadersCustomizers);

    return filterChainBuilder.build();
  }

  /**
   * Fails fast if any declared unprotected path would also match the login endpoint. This chain is
   * always ordered first ({@code ORDER_UNPROTECTED}) and unconditionally disables CSRF ({@code
   * .csrf(AbstractHttpConfigurer::disable)}) for whatever it matches — Spring's {@code
   * FilterChainProxy} routes a matching request here and never reaches the webapp chain that
   * actually enforces CSRF on {@code /login} (see {@link
   * SecurityFilterChainSupport#csrfEnforcedPaths}). An overlapping declaration would therefore
   * silently defeat the unconditional login-CSRF protection ADR-0027 requires
   * (camunda/security-testing-findings#281), which is why this is rejected at startup rather than
   * silently tolerated or filtered out of the matcher.
   */
  private static void rejectLoginPathOverlap(final Set<String> unprotectedPaths) {
    final var loginPath = PathContainer.parsePath(LOGIN_URL);
    final var offendingPattern =
        unprotectedPaths.stream()
            .filter(pattern -> PathPatternParser.defaultInstance.parse(pattern).matches(loginPath))
            .findFirst();
    if (offendingPattern.isPresent()) {
      throw new IllegalStateException(
          "SecurityPathPort#unprotectedPaths() declares '"
              + offendingPattern.get()
              + "', which matches the login endpoint ("
              + LOGIN_URL
              + "). The login endpoint requires a valid CSRF token unconditionally"
              + " (camunda/security-testing-findings#281) and must not be declared as an"
              + " unprotected path — remove or narrow this pattern.");
    }
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
