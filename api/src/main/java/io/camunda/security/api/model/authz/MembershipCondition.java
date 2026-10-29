/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.io.Serializable;
import java.util.Objects;

/**
 * Requires an attribute of the resource being accessed to share at least one value with an operand.
 * A resource that has no value for the attribute doesn't meet the condition (ADR-0041).
 *
 * @param attribute the attribute of the resource
 * @param operand the values to compare with
 */
public record MembershipCondition(ResourceAttribute attribute, Operand operand)
    implements Serializable {

  public MembershipCondition {
    Objects.requireNonNull(attribute, "attribute");
    Objects.requireNonNull(operand, "operand");
  }
}
