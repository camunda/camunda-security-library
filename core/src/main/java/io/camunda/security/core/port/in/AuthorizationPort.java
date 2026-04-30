/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.core.authorization.Authorization;
import io.camunda.security.core.authorization.CamundaAuthentication;
import io.camunda.security.core.authorization.ResourceAccess;

/**
 * Inbound port for authorization decisions. Callers ask whether a principal is permitted to perform
 * the requested {@link Authorization} (which carries the permission, resource type, and resource
 * ids being checked).
 *
 * <p>Implementations may consult host-supplied data (typically via {@link
 * io.camunda.security.core.port.out.AuthorizationRepositoryPort}), apply caching, or layer in
 * additional cross-cutting concerns.
 */
public interface AuthorizationPort {

  <T> ResourceAccess lookup(CamundaAuthentication authentication, Authorization<T> required);
}
