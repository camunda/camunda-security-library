/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.listOrEmpty;
import static io.camunda.security.api.model.policy.PolicyValidation.requireIds;

import java.util.List;

/**
 * Entities to delete. Memberships and authorizations are identified by their identity, see {@link
 * PolicyMembership} and {@link PolicyAuthorizationKey}.
 */
public record PolicyDeletions(
    List<String> tenantIds,
    List<String> roleIds,
    List<String> groupIds,
    List<String> mappingRuleIds,
    List<PolicyMembership> memberships,
    List<PolicyAuthorizationKey> authorizations) {

  public PolicyDeletions {
    tenantIds = requireIds(listOrEmpty(tenantIds), "tenantIds");
    roleIds = requireIds(listOrEmpty(roleIds), "roleIds");
    groupIds = requireIds(listOrEmpty(groupIds), "groupIds");
    mappingRuleIds = requireIds(listOrEmpty(mappingRuleIds), "mappingRuleIds");
    memberships = listOrEmpty(memberships);
    authorizations = listOrEmpty(authorizations);
  }
}
