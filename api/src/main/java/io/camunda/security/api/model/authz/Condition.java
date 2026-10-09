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
 * Requires an attribute of a resource to have a value in common with an operand. Both sides may be
 * multi-valued, so the condition is met when their values overlap. A resource that does not provide
 * the attribute does not meet the condition.
 *
 * @param attribute the attribute of the resource
 * @param operand the literal or principal-derived values to compare with
 */
public record Condition(ResourceAttribute attribute, Operand operand) implements Serializable {

  public Condition {
    Objects.requireNonNull(attribute, "attribute");
    Objects.requireNonNull(operand, "operand");
  }
}
