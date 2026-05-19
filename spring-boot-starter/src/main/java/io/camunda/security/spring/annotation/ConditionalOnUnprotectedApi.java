/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.annotation;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.UNPROTECTED_API_PROPERTY;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import java.lang.annotation.*;
import java.util.Optional;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@Documented
@Conditional(ConditionalOnUnprotectedApi.ApiUnprotectedCondition.class)
public @interface ConditionalOnUnprotectedApi {

  class ApiUnprotectedCondition implements Condition {
    @Override
    public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
      final Environment env = context.getEnvironment();
      return Optional.ofNullable(env.getProperty(UNPROTECTED_API_PROPERTY, Boolean.class))
          .orElse(AuthenticationConfiguration.DEFAULT_UNPROTECTED_API);
    }
  }
}
