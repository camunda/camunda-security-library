/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.authz;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * A role membership that applies to a resource only if all of its {@code conditions} are met by the
 * resource. Without conditions it applies to every resource. Conditions of a membership compare
 * with literal values only.
 *
 * @param roleId the ID of the role the principal holds
 * @param conditions the conditions that are AND-combined; empty means the membership applies
 *     everywhere
 */
public record RoleMembership(String roleId, List<Condition> conditions) implements Serializable {

  public RoleMembership {
    Objects.requireNonNull(roleId, "roleId");
    conditions = conditions == null ? List.of() : List.copyOf(conditions);
    for (final Condition condition : conditions) {
      if (!(condition.operand() instanceof Operand.Values)) {
        throw new IllegalArgumentException(
            "Conditions of a role membership only support literal values, but the condition on "
                + condition.attribute()
                + " has operand "
                + condition.operand());
      }
    }
  }
}
