/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.util.regex.Pattern;

/**
 * One entry under {@code camunda.security.physical-tenants[]}. Carries the tenant id (used as the
 * path segment under {@code /t/{id}/**}) and the tenant-scoped IDP profile.
 *
 * <p>The top-level {@link AuthenticationConfiguration#getOidc()} slot is unchanged and remains the
 * authoritative default profile for non-tenant-prefixed requests; per-tenant entries here are
 * strictly additive. See ADR-0011.
 */
public class PhysicalTenantConfiguration {

  static final Pattern ID_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+");

  private String id;
  private OidcConfiguration oidc = new OidcConfiguration();

  public String getId() {
    return id;
  }

  public void setId(final String id) {
    if (id != null && !ID_PATTERN.matcher(id).matches()) {
      throw new IllegalArgumentException(
          "Invalid physical-tenant id '"
              + id
              + "': must match "
              + ID_PATTERN.pattern()
              + " (used as a URL path segment).");
    }
    this.id = id;
  }

  public OidcConfiguration getOidc() {
    return oidc;
  }

  public void setOidc(final OidcConfiguration oidc) {
    this.oidc = oidc;
  }
}
