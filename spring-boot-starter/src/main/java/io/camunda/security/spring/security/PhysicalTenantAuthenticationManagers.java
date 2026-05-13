/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import java.util.Map;
import org.springframework.security.authentication.AuthenticationManager;

/**
 * Overridable holder for the per-tenant {@link AuthenticationManager} map consumed by {@link
 * PhysicalTenantOidcApiSecurityConfiguration}. The default bean is built from each tenant's {@code
 * OidcConfiguration}; tests or hosts that need to substitute the construction (for example to avoid
 * IDP network calls in tests) can register their own bean of this type to back off the default.
 */
public record PhysicalTenantAuthenticationManagers(Map<String, AuthenticationManager> byTenantId) {

  public PhysicalTenantAuthenticationManagers {
    byTenantId = Map.copyOf(byTenantId);
  }
}
