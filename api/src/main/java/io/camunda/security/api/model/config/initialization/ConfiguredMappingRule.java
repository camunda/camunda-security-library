/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.initialization;

public class ConfiguredMappingRule {

  private String mappingRuleId;
  private String claimName;
  private String claimValue;

  public ConfiguredMappingRule(
      final String mappingRuleId, final String claimName, final String claimValue) {
    ensureNotNullOrEmpty("mappingRuleId", mappingRuleId);
    ensureNotNullOrEmpty("claimName", claimName);
    ensureNotNullOrEmpty("claimValue", claimValue);
    this.mappingRuleId = mappingRuleId;
    this.claimName = claimName;
    this.claimValue = claimValue;
  }

  public String getMappingRuleId() {
    return mappingRuleId;
  }

  public void setMappingRuleId(final String mappingRuleId) {
    ensureNotNullOrEmpty("mappingRuleId", mappingRuleId);
    this.mappingRuleId = mappingRuleId;
  }

  public String getClaimName() {
    return claimName;
  }

  public void setClaimName(final String claimName) {
    ensureNotNullOrEmpty("claimName", claimName);
    this.claimName = claimName;
  }

  public String getClaimValue() {
    return claimValue;
  }

  public void setClaimValue(final String claimValue) {
    ensureNotNullOrEmpty("claimValue", claimValue);
    this.claimValue = claimValue;
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
