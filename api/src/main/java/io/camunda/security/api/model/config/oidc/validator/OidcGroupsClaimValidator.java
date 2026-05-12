/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc.validator;

/** Validates and normalizes OIDC groups-claim configuration values. */
public final class OidcGroupsClaimValidator {

  private OidcGroupsClaimValidator() {}

  public static void validate(final String groupsClaim) {
    if (groupsClaim == null || groupsClaim.isBlank()) {
      return;
    }

    if ("$".equals(groupsClaim)) {
      throw new IllegalArgumentException(
          "groupsClaim JSONPath must not refer to the root object: " + groupsClaim);
    }

    if (groupsClaim.startsWith("$")
        && !(groupsClaim.startsWith("$.") || groupsClaim.startsWith("$["))) {
      throw new IllegalArgumentException("Invalid groups claim JSONPath: " + groupsClaim);
    }

    if (!groupsClaim.startsWith("$") && groupsClaim.contains("'")) {
      throw new IllegalArgumentException(
          "groupsClaim must not contain single quotes when using plain claim syntax: "
              + groupsClaim);
    }
  }

  public static String sanitizeClaimPath(final String groupsClaim) {
    validate(groupsClaim);

    if (groupsClaim == null || groupsClaim.isBlank()) {
      return null;
    }

    return groupsClaim.startsWith("$") ? groupsClaim : "$['" + groupsClaim + "']";
  }
}
