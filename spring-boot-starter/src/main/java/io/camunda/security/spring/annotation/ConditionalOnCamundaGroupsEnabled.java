/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.annotation;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import io.camunda.security.api.model.config.AuthenticationConfiguration;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when some users get their groups from Camunda, i.e. {@link
 * AuthenticationConfiguration#isCamundaGroupsEnabled()}: the method is not OIDC, or an OIDC
 * provider has no groups claim. With several providers this considers each of them, not only the
 * {@code oidc} block.
 *
 * <p>Binds {@code camunda.security.authentication} via {@link Binder}, so the relaxed spellings of
 * every property match: camelCase ({@code groupsClaim}), kebab-case ({@code groups-claim}), and
 * environment variables ({@code CAMUNDA_SECURITY_AUTHENTICATION_OIDC_GROUPSCLAIM}). A plain
 * {@code @ConditionalOnExpression}'s SpEL {@code ${...}} placeholder resolution performs an
 * exact-key lookup and does not apply Spring Boot's relaxed binding, which previously caused the
 * kebab-case form to be silently ignored.
 */
@Target({TYPE, METHOD})
@Retention(RUNTIME)
@Documented
@Conditional(ConditionalOnCamundaGroupsEnabled.CamundaGroupsEnabledCondition.class)
public @interface ConditionalOnCamundaGroupsEnabled {

  final class CamundaGroupsEnabledCondition implements Condition {

    private static final String AUTHENTICATION_PROPERTIES = "camunda.security.authentication";

    @Override
    public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
      return Binder.get(context.getEnvironment())
          .bind(AUTHENTICATION_PROPERTIES, Bindable.of(AuthenticationConfiguration.class))
          .orElseGet(AuthenticationConfiguration::new)
          .isCamundaGroupsEnabled();
    }
  }
}
