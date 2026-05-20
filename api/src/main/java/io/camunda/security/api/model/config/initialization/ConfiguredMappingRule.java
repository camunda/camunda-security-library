/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

public record ConfiguredMappingRule(String mappingRuleId, String claimName, String claimValue) {
  public ConfiguredMappingRule {
    ensureNotNullOrEmpty("mappingRuleId", mappingRuleId);
    ensureNotNullOrEmpty("claimName", claimName);
    ensureNotNullOrEmpty("claimValue", claimValue);
  }

  private static void ensureNotNullOrEmpty(final String property, final String value) {
    if (value == null) {
      throw new IllegalArgumentException(property + " must not be null");
    }
    if (value.isEmpty()) {
      throw new IllegalArgumentException(property + " must not be empty");
    }
  }
}
