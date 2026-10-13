/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.requireId;

/** A mapping rule that maps an external claim to internal roles and groups. */
public record PolicyMappingRule(
    String mappingRuleId, String name, String claimName, String claimValue) {

  public PolicyMappingRule {
    requireId(mappingRuleId, "mappingRuleId");
  }
}
