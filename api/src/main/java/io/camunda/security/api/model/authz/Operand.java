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
import java.util.Set;

/**
 * The values a {@link MembershipCondition} compares a resource attribute with: fixed values, or
 * values taken from the caller when the condition is evaluated.
 */
public sealed interface Operand extends Serializable permits Operand.Values, Operand.Principal {

  /**
   * Fixed values.
   *
   * @param values the values; at least one, none of them {@code null}
   */
  record Values(Set<String> values) implements Operand {

    public Values {
      Objects.requireNonNull(values, "values");
      if (values.isEmpty()) {
        throw new IllegalArgumentException(
            "An operand needs at least one value; a condition without values can never be met.");
      }
      values = Set.copyOf(values);
    }
  }

  /**
   * The values of one attribute of the caller.
   *
   * @param attribute the attribute of the caller that provides the values
   */
  record Principal(PrincipalAttribute attribute) implements Operand {

    public Principal {
      Objects.requireNonNull(attribute, "attribute");
    }
  }
}
