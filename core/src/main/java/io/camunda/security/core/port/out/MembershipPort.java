/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.auth.Memberships;
import java.util.Map;

/**
 * Outbound port the host implements to resolve group, role, tenant, and mapping-rule memberships
 * for a principal. The library's authentication converters call this port; the host owns where the
 * data comes from (search index, RDBMS, in-memory, …).
 */
public interface MembershipPort {

  /** Resolves memberships for an OIDC principal identified by token claims. */
  Memberships resolveMemberships(
      Map<String, Object> tokenClaims, String principalId, PrincipalType principalType);

  /** Resolves memberships for a username/password principal. */
  Memberships resolveMembershipsForUser(String username);

  enum PrincipalType {
    USER,
    CLIENT
  }
}
