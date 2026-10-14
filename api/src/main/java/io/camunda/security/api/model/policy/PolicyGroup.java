/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.requireId;

/** A group as projected from the policy source of truth. */
public record PolicyGroup(String groupId, String name, String description) {

  public PolicyGroup {
    requireId(groupId, "groupId");
  }
}
