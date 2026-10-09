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
 * The right-hand side of a {@link Condition}: either literal values, or values taken from the
 * authenticated principal when the condition is evaluated.
 */
public sealed interface Operand extends Serializable permits Operand.Values, Operand.Principal {

  /**
   * Literal values.
   *
   * @param values the values; none of them is {@code null}
   */
  record Values(Set<String> values) implements Operand {

    public Values {
      Objects.requireNonNull(values, "values");
      values = Set.copyOf(values);
    }
  }

  /**
   * The values of one attribute of the authenticated principal.
   *
   * @param attribute the principal attribute that provides the values
   */
  record Principal(PrincipalAttribute attribute) implements Operand {

    public Principal {
      Objects.requireNonNull(attribute, "attribute");
    }
  }
}
