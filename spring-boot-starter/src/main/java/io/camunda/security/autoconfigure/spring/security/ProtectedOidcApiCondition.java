/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.autoconfigure.spring.security;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Condition that matches when {@code camunda.security.authentication.method=oidc} AND {@code
 * camunda.security.authentication.unprotected-api} is not {@code true}.
 */
final class ProtectedOidcApiCondition implements Condition {

  @Override
  public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
    final String method =
        context.getEnvironment().getProperty("camunda.security.authentication.method");
    final boolean unprotected =
        context
            .getEnvironment()
            .getProperty("camunda.security.authentication.unprotected-api", Boolean.class, false);
    return "oidc".equalsIgnoreCase(method) && !unprotected;
  }
}
