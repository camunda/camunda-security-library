/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.annotation;

import static io.camunda.security.api.model.config.oidc.OidcConfiguration.GROUPS_CLAIM_PROPERTY;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when no OIDC groups claim is configured, i.e. Camunda's own group model is in effect
 * rather than group membership being derived from an external OIDC claim.
 *
 * <p>Resolves {@link
 * io.camunda.security.api.model.config.oidc.OidcConfiguration#GROUPS_CLAIM_PROPERTY} via {@link
 * Binder} with a relaxed {@link ConfigurationPropertyName} so that both the camelCase ({@code
 * groupsClaim}) and kebab-case ({@code groups-claim}) property spellings match identically. A plain
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
    @Override
    public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
      final Binder binder = Binder.get(context.getEnvironment());
      final ConfigurationPropertyName propertyName =
          ConfigurationPropertyName.adapt(GROUPS_CLAIM_PROPERTY, '.');
      final String groupsClaim = binder.bind(propertyName, Bindable.of(String.class)).orElse(null);
      return groupsClaim == null || groupsClaim.isBlank();
    }
  }
}
