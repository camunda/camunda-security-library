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
 * What a {@link MembershipCondition} compares a resource attribute with.
 *
 * <p>The interface is sealed so that new kinds of operand can be added later, such as a set of
 * values. A host that can't evaluate an operand denies (ADR-0041).
 *
 * <p>Like the other model types, {@code Operand} has no Jackson annotations. A host that stores a
 * {@code CamundaAuthentication} as JSON must register a deserializer for {@code Operand}, or
 * reading it back fails. {@code CamundaAuthenticationJacksonTest} in the starter shows one.
 */
public sealed interface Operand extends Serializable permits Operand.Equals {

  /**
   * One value that the resource attribute must equal.
   *
   * <p>The comparison is literal. In particular, {@code *} is not a wildcard: a membership that
   * applies to every resource is a global role membership, not a conditional one (ADR-0041).
   *
   * @param value the value; not blank
   */
  record Equals(String value) implements Operand {

    public Equals {
      Objects.requireNonNull(value, "value");
      if (value.isBlank()) {
        throw new IllegalArgumentException(
            "An operand needs a value; a blank value can never be met.");
      }
    }
  }
}
