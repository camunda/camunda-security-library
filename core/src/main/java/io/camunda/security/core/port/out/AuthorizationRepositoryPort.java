/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.core.authorization.Authorization;
import io.camunda.security.core.authorization.CamundaAuthentication;
import io.camunda.security.core.authorization.ResourceAccess;

/**
 * Outbound port the host implements to look up an authorization decision from its own data store
 * (search index, broker state, RDBMS, …). The library's reference {@link
 * io.camunda.security.core.port.in.AuthorizationPort} implementation delegates here for the actual
 * data fetch — hosts that need different cross-cutting behaviour can override the inbound port
 * directly and skip this one.
 *
 * <p>Same shape as {@link io.camunda.security.core.port.in.AuthorizationPort} on purpose: the
 * inbound port is what the library's filters call; this outbound port is what the host satisfies.
 * Keeping them separate lets the library evolve the inbound port (caching, instrumentation) without
 * forcing host implementations to change.
 */
public interface AuthorizationRepositoryPort {

  <T> ResourceAccess lookup(CamundaAuthentication authentication, Authorization<T> required);
}
