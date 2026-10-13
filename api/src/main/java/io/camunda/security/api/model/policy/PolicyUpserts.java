/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.policy;

import static io.camunda.security.api.model.policy.PolicyValidation.listOrEmpty;

import java.util.List;

/** Entities to create or update. Missing sections deserialise to empty lists. */
public record PolicyUpserts(
    List<PolicyTenant> tenants,
    List<PolicyRole> roles,
    List<PolicyGroup> groups,
    List<PolicyMappingRule> mappingRules,
    List<PolicyMembership> memberships,
    List<PolicyAuthorization> authorizations) {

  public PolicyUpserts {
    tenants = listOrEmpty(tenants);
    roles = listOrEmpty(roles);
    groups = listOrEmpty(groups);
    mappingRules = listOrEmpty(mappingRules);
    memberships = listOrEmpty(memberships);
    authorizations = listOrEmpty(authorizations);
  }
}
