/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP_API;

import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityAutoConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import io.camunda.security.spring.handler.LoggingAuthenticationFailureHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.annotation.Order;
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

/** Filter chain that protects API paths with OIDC JWT bearer authentication. */
@AutoConfiguration
@AutoConfigureAfter(CamundaSecurityAutoConfiguration.class)
@Conditional(ProtectedOidcApiCondition.class)
public class OidcApiSecurityAutoConfiguration {

  private static final Logger LOG = LoggerFactory.getLogger(OidcApiSecurityAutoConfiguration.class);

  @Bean
  @Order(ORDER_WEBAPP_API)
  public SecurityFilterChain oidcApiSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final JwtDecoder jwtDecoder,
      final ObjectProvider<OidcResourceServerCustomizer> resourceServerCustomizers,
      final CamundaSecurityLibraryProperties properties,
      final SecurityPathPort pathPort)
      throws Exception {
    LOG.info("The API is protected by OIDC JWT authentication.");
    final var filterChainBuilder =
        http.securityMatcher(pathPort.apiPaths().toArray(String[]::new))
            .authorizeHttpRequests(
                auth ->
                    auth.requestMatchers(pathPort.unprotectedApiPaths().toArray(String[]::new))
                        .permitAll()
                        .anyRequest()
                        .authenticated())
            .oauth2ResourceServer(
                oauth2 -> {
                  oauth2
                      .jwt(jwt -> jwt.decoder(jwtDecoder))
                      .authenticationEntryPoint(authFailureHandler)
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
