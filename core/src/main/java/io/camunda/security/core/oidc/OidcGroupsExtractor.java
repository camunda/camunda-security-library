/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.oidc;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.InvalidPathException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;
import io.camunda.security.api.model.config.oidc.validator.OidcGroupsClaimValidator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Extracts group identifiers from OIDC claims using a configured claim path. */
public final class OidcGroupsExtractor {

  public static final String DERIVED_GROUPS_ARE_NOT_STRING_ARRAY =
      "Group list derived from (%s) is not a string array. Please check your OIDC configuration.";

  private static final Configuration JSON_PATH_CONFIGURATION =
      Configuration.builder().options(Option.DEFAULT_PATH_LEAF_TO_NULL).build();

  private final String groupsClaim;

  public OidcGroupsExtractor(final String groupsClaim) {
    this.groupsClaim = OidcGroupsClaimValidator.sanitizeClaimPath(groupsClaim);

    if (this.groupsClaim != null) {
      try {
        JsonPath.compile(this.groupsClaim);
      } catch (final InvalidPathException e) {
        throw new IllegalArgumentException(e.getMessage(), e);
      }
    }
  }

  public List<String> extract(final Map<String, Object> claims) {
    if (groupsClaim == null) {
      return null;
    }

    final List<String> groups = new ArrayList<>();

    try {
      final Object claimGroups =
          JsonPath.using(JSON_PATH_CONFIGURATION).parse(claims).read(groupsClaim);
      if (claimGroups == null) {
        return groups;
      }

      if (claimGroups instanceof final String group) {
        groups.add(group);
        return groups;
      }

      if (claimGroups instanceof final List<?> list) {
        for (final Object value : list) {
          if (value instanceof final String group) {
            groups.add(group);
          } else {
            throw new IllegalArgumentException(
                DERIVED_GROUPS_ARE_NOT_STRING_ARRAY.formatted(groupsClaim));
          }
        }
        return groups;
      }

      throw new IllegalArgumentException(
          DERIVED_GROUPS_ARE_NOT_STRING_ARRAY.formatted(groupsClaim));
    } catch (final PathNotFoundException ignored) {
      return groups;
    }
  }

  public String getGroupsClaim() {
    return groupsClaim;
  }
}
