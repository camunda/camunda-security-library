/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authorization;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The authenticated principal as the library sees it. Hosts construct one of these from whatever
 * authentication shape they use (Spring Security {@code Authentication}, custom claims, etc.) and
 * pass it into {@link io.camunda.security.core.port.in.AuthorizationPort#lookup}.
 *
 * <p>Either {@code authenticatedUsername} or {@code authenticatedClientId} is typically set; {@code
 * anonymous=true} indicates an unauthenticated principal.
 */
public record CamundaAuthentication(
    String authenticatedUsername,
    String authenticatedClientId,
    boolean anonymous,
    Set<String> authenticatedRoleIds,
    Set<String> authenticatedGroupIds,
    Set<String> authenticatedMappingRuleIds,
    Map<String, Object> claims) {

  public CamundaAuthentication {
    if (anonymous && (authenticatedUsername != null || authenticatedClientId != null)) {
      throw new IllegalArgumentException(
          "Anonymous authentication must not define username or clientId.");
    }
    if (!anonymous && authenticatedUsername != null && authenticatedClientId != null) {
      throw new IllegalArgumentException(
          "Non-anonymous authentication must not define both username and clientId.");
    }
    authenticatedRoleIds =
        authenticatedRoleIds == null ? Set.of() : Set.copyOf(authenticatedRoleIds);
    authenticatedGroupIds =
        authenticatedGroupIds == null ? Set.of() : Set.copyOf(authenticatedGroupIds);
    authenticatedMappingRuleIds =
        authenticatedMappingRuleIds == null ? Set.of() : Set.copyOf(authenticatedMappingRuleIds);
    claims = claims == null ? Map.of() : Map.copyOf(claims);
  }

  public static CamundaAuthentication unauthenticated() {
    return new CamundaAuthentication(null, null, true, Set.of(), Set.of(), Set.of(), Map.of());
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private String authenticatedUsername;
    private String authenticatedClientId;
    private boolean anonymous;
    private final Set<String> authenticatedRoleIds = new HashSet<>();
    private final Set<String> authenticatedGroupIds = new HashSet<>();
    private final Set<String> authenticatedMappingRuleIds = new HashSet<>();
    private final Map<String, Object> claims = new HashMap<>();

    private Builder() {}

    public Builder authenticatedUsername(final String authenticatedUsername) {
      this.authenticatedUsername = authenticatedUsername;
      return this;
    }

    public Builder authenticatedClientId(final String authenticatedClientId) {
      this.authenticatedClientId = authenticatedClientId;
      return this;
    }

    public Builder anonymous(final boolean anonymous) {
      this.anonymous = anonymous;
      return this;
    }

    public Builder authenticatedRoleIds(final Set<String> ids) {
      authenticatedRoleIds.clear();
      if (ids != null) {
        authenticatedRoleIds.addAll(ids);
      }
      return this;
    }

    public Builder authenticatedGroupIds(final Set<String> ids) {
      authenticatedGroupIds.clear();
      if (ids != null) {
        authenticatedGroupIds.addAll(ids);
      }
      return this;
    }

    public Builder authenticatedMappingRuleIds(final Set<String> ids) {
      authenticatedMappingRuleIds.clear();
      if (ids != null) {
        authenticatedMappingRuleIds.addAll(ids);
      }
      return this;
    }

    public Builder claims(final Map<String, Object> claims) {
      this.claims.clear();
      if (claims != null) {
        this.claims.putAll(claims);
      }
      return this;
    }

    public CamundaAuthentication build() {
      return new CamundaAuthentication(
          authenticatedUsername,
          authenticatedClientId,
          anonymous,
          authenticatedRoleIds,
          authenticatedGroupIds,
          authenticatedMappingRuleIds,
          claims);
    }
  }
}
