/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;

/**
 * Resolves the per-tenant {@link AuthenticationManager} for a request whose path matches {@code
 * /physical-tenants/{tenantId}/**}. The tenant→manager map is materialised once at chain
 * construction from the configured {@code camunda.security.physical-tenants[]} list — see ADR-0011.
 *
 * <p>Because the per-tenant chain's {@code securityMatcher} is narrowed to configured tenant ids,
 * {@link #resolve(HttpServletRequest)} is only invoked for known tenants. An unknown id reaching
 * this resolver indicates a wiring mistake and surfaces as an {@link IllegalStateException}.
 */
final class PhysicalTenantAuthenticationManagerResolver
    implements AuthenticationManagerResolver<HttpServletRequest> {

  private static final Pattern TENANT_PATH_PATTERN =
      Pattern.compile("^/physical-tenants/([^/]+)(?:/.*)?$");

  private final Map<String, AuthenticationManager> managersByTenantId;

  PhysicalTenantAuthenticationManagerResolver(
      final Map<String, AuthenticationManager> managersByTenantId) {
    this.managersByTenantId = Map.copyOf(managersByTenantId);
  }

  @Override
  public AuthenticationManager resolve(final HttpServletRequest request) {
    final String path = request.getRequestURI();
    final Matcher matcher = TENANT_PATH_PATTERN.matcher(path);
    if (!matcher.matches()) {
      throw new IllegalStateException(
          "PhysicalTenantAuthenticationManagerResolver invoked on non-tenant path: " + path);
    }
    final String tenantId = matcher.group(1);
    final AuthenticationManager manager = managersByTenantId.get(tenantId);
    if (manager == null) {
      throw new IllegalStateException(
          "No AuthenticationManager configured for physical tenant '" + tenantId + "'.");
    }
    return manager;
  }
}
