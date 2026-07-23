/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.authz.Authorization;
import io.camunda.security.api.model.authz.ResourceType;
import java.util.Set;

/**
 * Outbound port the host implements to return the authorization records held for a principal on a
 * given resource type. The library's {@code ResourcePermissionService} aggregates these records to
 * answer permission questions; the host owns where the records come from (search index, broker
 * state, RDBMS, …).
 *
 * <p>Implementations should resolve the principal's identity transitively — direct user/client
 * grants, plus grants reachable via the principal's groups, roles, and mapping rules — and return
 * every matching record for the requested {@link ResourceType}.
 */
public interface AuthorizationRepositoryPort {

  Set<Authorization> findAuthorizations(
      CamundaAuthentication authentication, ResourceType resourceType);

  void createAuthorization(CamundaAuthentication authentication, Authorization authorization);
}
