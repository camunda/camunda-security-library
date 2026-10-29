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
 * A membership that applies only to resources that meet all of its conditions (ADR-0041). A global
 * membership is not a {@code ConditionalMembership} with no conditions; it stays in the existing ID
 * lists, so a conditional membership always carries at least one condition.
 *
 * @param id the ID of the entity the principal is a member of, for example a role ID
 * @param conditions the conditions, all of which must be met; at least one
 */
public record ConditionalMembership(String id, List<MembershipCondition> conditions)
    implements Serializable {

  public ConditionalMembership {
    Objects.requireNonNull(id, "id");
    if (id.isBlank()) {
      throw new IllegalArgumentException("A conditional membership needs a non-blank id.");
    }
    Objects.requireNonNull(conditions, "conditions");
    if (conditions.isEmpty()) {
      throw new IllegalArgumentException(
          "Conditional membership '%s' has no conditions; a global membership belongs in the ID lists."
              .formatted(id));
    }
    conditions = List.copyOf(conditions);
  }
}
