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

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;

/**
 * Matches when the configured authentication method is not {@code oidc}.
 *
 * <p>Audited against the relaxed-binding gap described in <a
 * href="https://github.com/camunda/camunda-security-library/issues/554">#554</a>: the referenced
 * property, {@code camunda.security.authentication.method}, has no camelCase word boundary, so its
 * camelCase and kebab-case YAML spellings are identical and this {@code @ConditionalOnExpression}'s
 * exact-key placeholder lookup cannot diverge from relaxed binding the way {@code groupsClaim} /
 * {@code groups-claim} did. If this property is ever renamed to something with an internal word
 * boundary, switch this condition to the {@code Binder}-based pattern used by {@link
 * ConditionalOnCamundaGroupsEnabled} instead of {@code @ConditionalOnExpression}.
 */
@Target({TYPE, METHOD})
@Retention(RUNTIME)
@Documented
@ConditionalOnExpression("'${camunda.security.authentication.method:}'.toLowerCase() != 'oidc'")
public @interface ConditionalOnInternalUserManagement {}
