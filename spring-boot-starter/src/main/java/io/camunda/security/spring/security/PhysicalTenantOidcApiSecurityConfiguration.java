/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_PHYSICAL_TENANT_WEBAPP_API;

import io.camunda.security.api.model.config.OidcConfiguration;
import io.camunda.security.api.model.config.PhysicalTenantConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.handler.AuthFailureHandler;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Single tenant-aware filter chain that serves {@code /physical-tenants/{tenantId}/**} for every
 * configured physical tenant when {@code method=oidc}. Per-tenant authentication is dispatched via
 * a {@link PhysicalTenantAuthenticationManagerResolver}. See ADR-0011.
 *
 * <p>Activation: hosts opt in by explicit {@code @Import} per ADR-0008. If imported but {@code
 * camunda.security.physical-tenants} is empty, the chain bean fails fast at construction — an empty
 * list with this configuration imported is a wiring mistake, not a silent no-op.
 */
@Configuration
@Conditional(ProtectedOidcApiCondition.class)
public class PhysicalTenantOidcApiSecurityConfiguration {

  private static final Logger LOG =
      LoggerFactory.getLogger(PhysicalTenantOidcApiSecurityConfiguration.class);

  @Bean
  @ConditionalOnMissingBean
  public PhysicalTenantAuthenticationManagers physicalTenantAuthenticationManagers(
      final CamundaSecurityLibraryProperties properties) {
    final List<PhysicalTenantConfiguration> tenants = requireConfiguredTenants(properties);
    final Map<String, AuthenticationManager> managersByTenantId = new LinkedHashMap<>();
    for (final PhysicalTenantConfiguration tenant : tenants) {
      managersByTenantId.put(tenant.getId(), authenticationManagerFor(tenant));
      LOG.info(
          "Registered physical tenant OIDC AuthenticationManager for tenant '{}'.", tenant.getId());
    }
    return new PhysicalTenantAuthenticationManagers(managersByTenantId);
  }

  @Bean
  @Order(ORDER_PHYSICAL_TENANT_WEBAPP_API)
  public SecurityFilterChain physicalTenantOidcApiSecurityFilterChain(
      final HttpSecurity http,
      final AuthFailureHandler authFailureHandler,
      final PhysicalTenantAuthenticationManagers managers,
      final CamundaSecurityLibraryProperties properties)
      throws Exception {
    final List<PhysicalTenantConfiguration> tenants = requireConfiguredTenants(properties);

    final List<RequestMatcher> tenantMatchers = new ArrayList<>(tenants.size());
    for (final PhysicalTenantConfiguration tenant : tenants) {
      tenantMatchers.add(
          PathPatternRequestMatcher.withDefaults()
              .matcher("/physical-tenants/" + tenant.getId() + "/**"));
    }

    final PhysicalTenantAuthenticationManagerResolver resolver =
        new PhysicalTenantAuthenticationManagerResolver(managers.byTenantId());

    return http.securityMatcher(new OrRequestMatcher(tenantMatchers))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth2 ->
                oauth2
                    .authenticationManagerResolver(resolver)
                    .authenticationEntryPoint(authFailureHandler)
                    .accessDeniedHandler(authFailureHandler))
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.NEVER))
        .requestCache(cache -> cache.requestCache(new NullRequestCache()))
        .csrf(AbstractHttpConfigurer::disable)
        .cors(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .anonymous(AbstractHttpConfigurer::disable)
        .oauth2Login(AbstractHttpConfigurer::disable)
        .oidcLogout(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .build();
  }

  private static List<PhysicalTenantConfiguration> requireConfiguredTenants(
      final CamundaSecurityLibraryProperties properties) {
    final List<PhysicalTenantConfiguration> tenants = properties.getPhysicalTenants();
    if (tenants == null || tenants.isEmpty()) {
      throw new IllegalStateException(
          "PhysicalTenantOidcApiSecurityConfiguration is imported but"
              + " camunda.security.physical-tenants is empty.");
    }
    for (final PhysicalTenantConfiguration tenant : tenants) {
      if (tenant.getId() == null || tenant.getId().isBlank()) {
        throw new IllegalStateException(
            "Physical tenant declared with no id under camunda.security.physical-tenants[].");
      }
    }
    return tenants;
  }

  private static AuthenticationManager authenticationManagerFor(
      final PhysicalTenantConfiguration tenant) {
    return new ProviderManager(new JwtAuthenticationProvider(jwtDecoderFor(tenant)));
  }

  private static JwtDecoder jwtDecoderFor(final PhysicalTenantConfiguration tenant) {
    final OidcConfiguration oidc = tenant.getOidc();
    if (oidc.getJwkSetUri() != null && !oidc.getJwkSetUri().isBlank()) {
      return NimbusJwtDecoder.withJwkSetUri(oidc.getJwkSetUri()).build();
    }
    if (oidc.getIssuerUri() != null && !oidc.getIssuerUri().isBlank()) {
      return NimbusJwtDecoder.withIssuerLocation(oidc.getIssuerUri()).build();
    }
    throw new IllegalStateException(
        "Cannot build JwtDecoder for physical tenant '"
            + tenant.getId()
            + "': set either jwk-set-uri or issuer-uri under its oidc.* config.");
  }
}
