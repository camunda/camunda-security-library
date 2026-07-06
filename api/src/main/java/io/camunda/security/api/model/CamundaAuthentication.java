/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Represents the authentication context for a user or client in Camunda, including (where
 * appropriate) their username or client ID, group memberships, roles, tenants, mapping rules, and
 * associated claims.
 *
 * <p>Either {@code authenticatedUsername} or {@code authenticatedClientId} must be set, but not
 * both, unless the authentication represents an anonymous user {@code anonymousUser} in which case
 * both can be null.
 *
 * <p>Claim entries with {@code null} values — as emitted by some identity providers for unset
 * profile fields — are discarded during normalization: a null-valued claim is indistinguishable
 * from an absent claim for every consumer of this record.
 *
 * <p>Membership fields ({@code authenticatedGroupIds}, {@code authenticatedRoleIds}, {@code
 * authenticatedTenantIds}, {@code authenticatedMappingRuleIds}) may be supplied eagerly via the
 * corresponding builder methods, or lazily via the {@code *Supplier} builder methods — see
 * ADR-0011. Lazy fields are resolved at most once on the first read operation against the returned
 * list; the public accessor signature is unchanged in both cases.
 */
public record CamundaAuthentication(
    String authenticatedUsername,
    String authenticatedClientId,
    boolean anonymousUser,
    List<String> authenticatedGroupIds,
    List<String> authenticatedRoleIds,
    List<String> authenticatedTenantIds,
    List<String> authenticatedMappingRuleIds,
    Map<String, Object> claims)
    implements Serializable {

  public CamundaAuthentication {
    if (anonymousUser) {
      if (authenticatedUsername != null || authenticatedClientId != null) {
        throw new IllegalArgumentException(
            "Anonymous authentication must not define username or clientId.");
      }
    } else if (authenticatedUsername != null && authenticatedClientId != null) {
      throw new IllegalArgumentException(
          "Only one of username or clientId may be set for non-anonymous authentication.");
    }
    /*
     TODO this is currently not possible with usage of the "none()" methode.
     This will be fixed with: https://github.com/camunda/camunda-security-library/issues/96

      else if ((authenticatedUsername == null) && (authenticatedClientId == null)) {
      throw new IllegalArgumentException(
          "Exactly one of username or clientId must be set for non-anonymous authentication.");
    } */

    authenticatedGroupIds = listOrEmpty(authenticatedGroupIds);
    authenticatedRoleIds = listOrEmpty(authenticatedRoleIds);
    authenticatedTenantIds = listOrEmpty(authenticatedTenantIds);
    authenticatedMappingRuleIds = listOrEmpty(authenticatedMappingRuleIds);
    claims = immutableClaimsWithoutNullValues(claims);
  }

  /**
   * @return A log-safe, formatted principal string with either {@code user=<username>}, {@code
   *     client=<clientId>}, or {@code unknown}.
   */
  public String formattedPrincipal() {
    if (authenticatedUsername() != null) {
      return "user=" + authenticatedUsername();
    }
    if (authenticatedClientId() != null) {
      return "client=" + authenticatedClientId();
    }
    return "unknown";
  }

  private static <T> List<T> listOrEmpty(final List<T> values) {
    if (values == null) {
      return List.of();
    }
    if (values instanceof LazyList<?>) {
      return values;
    }
    return List.copyOf(values);
  }

  private static Map<String, Object> immutableClaimsWithoutNullValues(
      final Map<String, Object> claims) {
    if (claims == null) {
      return Map.of();
    }
    // Claims originate from external IdPs, which may emit JSON null claim values. All consumers
    // treat a null-valued claim as absent, so drop such entries — Map.copyOf rejects null values.
    final Map<String, Object> withoutNullValues = new LinkedHashMap<>(claims);
    withoutNullValues.values().removeIf(Objects::isNull);
    return Map.copyOf(withoutNullValues);
  }

  public boolean isAnonymous() {
    return anonymousUser;
  }

  public static CamundaAuthentication none() {
    return of(b -> b);
  }

  public static CamundaAuthentication anonymous() {
    return of(b -> b.anonymous(true));
  }

  public static CamundaAuthentication of(final Function<Builder, Builder> builderFunction) {
    return builderFunction.apply(new Builder()).build();
  }

  /**
   * Returns a {@link java.util.List} whose elements are resolved lazily by invoking {@code
   * supplier} at most once on the first read. Intended for converters that need to wire chained
   * lazy membership lookups via the {@code *Supplier} builder methods without exposing the
   * package-private {@link LazyList} type.
   */
  public static <T> java.util.List<T> lazyList(
      final java.util.function.Supplier<java.util.List<T>> supplier) {
    return LazyList.of(supplier);
  }

  public static final class Builder {

    private String username;
    private String clientId;
    private boolean anonymous;
    private final List<String> groupIds = new ArrayList<>();
    private final List<String> roleIds = new ArrayList<>();
    private final List<String> tenants = new ArrayList<>();
    private final List<String> mappingRules = new ArrayList<>();
    private Supplier<List<String>> groupIdsSupplier;
    private Supplier<List<String>> roleIdsSupplier;
    private Supplier<List<String>> tenantsSupplier;
    private Supplier<List<String>> mappingRulesSupplier;
    private Map<String, Object> claims;

    public Builder user(final String value) {
      username = value;
      return this;
    }

    public Builder clientId(final String value) {
      clientId = value;
      return this;
    }

    public Builder anonymous(final boolean value) {
      anonymous = value;
      return this;
    }

    public Builder group(final String value) {
      return groupIds(Collections.singletonList(value));
    }

    public Builder groupIds(final List<String> values) {
      if (values != null) {
        groupIds.addAll(values);
      }
      return this;
    }

    public Builder groupIdsSupplier(final Supplier<List<String>> supplier) {
      groupIdsSupplier = Objects.requireNonNull(supplier, "groupIds supplier must not be null");
      return this;
    }

    public Builder role(final String value) {
      return roleIds(Collections.singletonList(value));
    }

    public Builder roleIds(final List<String> values) {
      if (values != null) {
        roleIds.addAll(values);
      }
      return this;
    }

    public Builder roleIdsSupplier(final Supplier<List<String>> supplier) {
      roleIdsSupplier = Objects.requireNonNull(supplier, "roleIds supplier must not be null");
      return this;
    }

    public Builder tenant(final String tenant) {
      return tenants(Collections.singletonList(tenant));
    }

    public Builder tenants(final List<String> values) {
      if (values != null) {
        tenants.addAll(values);
      }
      return this;
    }

    public Builder tenantsSupplier(final Supplier<List<String>> supplier) {
      tenantsSupplier = Objects.requireNonNull(supplier, "tenants supplier must not be null");
      return this;
    }

    public Builder mappingRule(final String mappingRule) {
      return mappingRules(Collections.singletonList(mappingRule));
    }

    public Builder mappingRules(final List<String> values) {
      if (values != null) {
        mappingRules.addAll(values);
      }
      return this;
    }

    public Builder mappingRulesSupplier(final Supplier<List<String>> supplier) {
      mappingRulesSupplier =
          Objects.requireNonNull(supplier, "mappingRules supplier must not be null");
      return this;
    }

    public Builder claims(final Map<String, Object> value) {
      // Snapshot only — must tolerate null values; the canonical constructor normalizes.
      claims = value == null ? null : new LinkedHashMap<>(value);
      return this;
    }

    public CamundaAuthentication build() {
      return new CamundaAuthentication(
          username,
          clientId,
          anonymous,
          resolveMembershipField("groupIds", groupIds, groupIdsSupplier),
          resolveMembershipField("roleIds", roleIds, roleIdsSupplier),
          resolveMembershipField("tenants", tenants, tenantsSupplier),
          resolveMembershipField("mappingRules", mappingRules, mappingRulesSupplier),
          claims);
    }

    private static List<String> resolveMembershipField(
        final String fieldName, final List<String> eager, final Supplier<List<String>> supplier) {
      if (supplier != null) {
        if (!eager.isEmpty()) {
          throw new IllegalStateException(
              "Both eager values and a supplier were set for '"
                  + fieldName
                  + "'. Use one or the other.");
        }
        return new LazyList<>(supplier);
      }
      return List.copyOf(eager);
    }
  }
}
