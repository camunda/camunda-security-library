/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.AUTHENTICATION_METHOD_PROPERTY;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.UNPROTECTED_API_PROPERTY;

import io.camunda.security.api.model.config.AuthenticationMethod;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Condition that matches when {@code camunda.security.authentication.method=basic} AND {@code
 * camunda.security.authentication.unprotected-api} is not {@code true}.
 */
final class ProtectedBasicAuthApiCondition implements Condition {

  @Override
  public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
    final String method = context.getEnvironment().getProperty(AUTHENTICATION_METHOD_PROPERTY);
    final boolean unprotected =
        context.getEnvironment().getProperty(UNPROTECTED_API_PROPERTY, Boolean.class, false);
    return (method == null || AuthenticationMethod.BASIC.name().equalsIgnoreCase(method))
        && !unprotected;
  }
}
