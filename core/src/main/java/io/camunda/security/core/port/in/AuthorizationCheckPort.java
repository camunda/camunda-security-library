/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.Either;
import io.camunda.security.api.model.authz.AuthorizationRejection;
import io.camunda.security.core.auth.RequiredAuthorization;

/**
 * Inbound port for authorization checks. Returns {@link Either#right(Object) Either.right(null)}
 * when the principal is authorized, or {@link Either#left(Object) Either.left(rejection)} when
 * access is denied.
 *
 * <p>Inc 1 initial surface — batch-check methods deferred to Inc 2+.
 */
public interface AuthorizationCheckPort {

  <T> Either<AuthorizationRejection, Void> check(
      CamundaAuthentication authentication, RequiredAuthorization<T> authorization);
}
